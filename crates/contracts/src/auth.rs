//! DTO contracts of the internal authentication API (`/internal/authenticate*`, ADR-0007 §3).
//!
//! Shared by web (login screen) -> api internal auth calls. web sends (serializes) [`InternalAuthenticateRequest`] /
//! [`InternalAdminAuthenticateRequest`], and api receives (deserializes) them. Responses are
//! discriminated by the `result` tag and carry SSO/redirect information only on success. Building cookies (Secure/HttpOnly/
//! SameSite/TTL) and localizing error messages are the caller's (web's) job.
//!
//! `/internal/*` is an internal interface not exposed externally, so it is not included in OpenAPI (`utoipa::ToSchema`).

use serde::{Deserialize, Serialize};

/// Code put in the `/internal/*` error body when api **could not resolve the tenant** (MT28).
///
/// `/internal/*` has no tenant prefix, so it does not pass the §7 `TenantResolver` middleware and
/// `tenant_id` arrives as a body field. Nonexistent or `DISABLED` is rejected with 400, but it
/// **must be machine-distinguishable from other 400s (invalid body etc.)**: web turns only this into the 404
/// screen and everything else into 502 as "a web implementation/configuration error". Discriminating by the
/// description (for humans) would break silently the moment the wording is fixed.
///
/// If the value drifts between api and web, it merely reverts to "a nonexistent tenant becomes 502", which is easy to miss,
/// so it is defined once in `contracts`.
pub const UNKNOWN_TENANT_ERROR_CODE: &str = "unknown_tenant";

/// Request of the authorization flow resume API (`POST /internal/authorize/resume`, decision 2 of ADR-0018).
///
/// api's `/authorize` does not read browser cookies and puts a single-use, short-lived handle (`?auth_session=`)
/// on the redirect URL to web. web passes the handle and the value of its **own-domain host-only**
/// `sso_session_id` cookie to this API, and api does the handle exchange (single consumption), the SSO decision,
/// the consent check and code issuance (same response pattern as `/internal/authenticate`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAuthorizeResumeRequest {
    /// The flow's tenant (ADR-0009 §8). **Required**. api rejects a missing or invalid UUID with 400 (fail-closed; SEC4).
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// The single-use handle `/authorize` put on the redirect URL.
    pub handle: String,
    /// Value of web's host-only `sso_session_id` cookie (`None` if absent = not logged in).
    #[serde(default)]
    pub sso_session_id: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the authorization flow resume API. Discriminated by the `result` tag.
///
/// Responses with successful SSO restoration (`Redirect`, `ConsentRequired`) include `sso_absolute_ttl_secs`.
/// web uses it to **reissue** its `sso_session_id` as host-only. While `COOKIE_DOMAIN` (cleanup of the old ADR-0012
/// setup) is set, the reissue also sends a deletion of the old `Domain` cookie, so existing sessions that do not go
/// through an explicit login/logout also migrate to host-only at silent restoration, closing the exposure of the
/// bearer credential continuing to be sent under the old parent domain (stg etc.).
/// Hidden fields POSTed in a `response_mode=form_post` authorization response (G12).
///
/// `None` means `query` (302 to `redirect_to`). When `Some`, web renders an **auto-submitting form** with
/// `redirect_to` as the action and POSTs these fields.
///
/// The fields are not folded into the URL because `redirect_uri` itself may have a query, so
/// "where the RP's query ends and the authorization response begins" cannot be recovered from the URL.
/// In this shape, `redirect_to` **carries no authorization response parameters** (even if an overlooked path
/// 302s, the authorization code does not remain in history or `Referer`).
pub type FormPostFields = Vec<(String, String)>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAuthorizeResumeResponse {
    /// SSO valid and consented. 302 to `redirect_to` (RP URL) with a code already issued.
    Redirect {
        redirect_to: String,
        /// Hidden fields POSTed for `form_post` (G12). `None` means `query`.
        #[serde(default)]
        form_post: Option<FormPostFields>,
        sso_absolute_ttl_secs: u64,
    },
    /// The request cannot continue (not logged in or not consented with `prompt=none` etc.). Returns an error to the RP.
    /// As with `Redirect`, if `form_post` is `Some`, POST hidden fields to `redirect_to`
    /// (errors are also returned in the requested `response_mode`; G12). `None` means `query` (302 to `redirect_to`).
    ErrorRedirect {
        redirect_to: String,
        #[serde(default)]
        form_post: Option<FormPostFields>,
    },
    /// SSO valid but consent required. web turns `auth_session_id` into a host-only cookie and goes to `/consent`.
    ConsentRequired {
        auth_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// Authentication required. web turns `auth_session_id` into a host-only cookie and shows the login form.
    LoginRequired { auth_session_id: String },
    /// Authenticated, but use of this app is not permitted (ADR-0054). ⚠ **Not returned to the RP.**
    /// web refuses on assay's screen: to the user it is "I got in and was then kicked out", so it shows the fact that
    /// authentication passed, the app name, and a way to ask the admin.
    ApplicationNotPermitted { application_name: String },
    /// The handle is invalid, expired or used (start over from `/authorize`).
    ExpiredHandle,
    /// api internal error.
    Internal,
}

/// Request of the authorization flow continue API (`POST /internal/authorize/continue`).
///
/// Used when, after the login screen was shown, authentication was completed in another tab and the original tab is reopened.
/// The handle was consumed on first receipt, so web passes the values of the host-only `auth_session_id` cookie and the
/// `sso_session_id` cookie, and api tries SSO restoration with the same authorization request. The response is
/// [`InternalAuthorizeResumeResponse`] (`expired_handle` means `auth_session_id` is invalid or expired).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAuthorizeContinueRequest {
    /// The flow's tenant (ADR-0009 §8). **Required**. api rejects a missing or invalid UUID with 400.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Value of web's host-only `auth_session_id` cookie.
    pub auth_session_id: String,
    /// Value of web's host-only `sso_session_id` cookie.
    #[serde(default)]
    pub sso_session_id: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Request of the login screen context API (`POST /internal/authorize/login-context`; G12).
///
/// `login_hint` / `ui_locales` received by `/authorize` are saved in the auth_session, but web drops state in
/// resume's 303 (the redirect removing the handle from the URL), so they are not at hand when rendering the login
/// screen. web passes the value of the host-only `auth_session_id` cookie to fetch them again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAuthorizeLoginContextRequest {
    /// The flow's tenant (ADR-0009 §8). **Required**. api rejects a missing or invalid UUID with 400.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Value of web's host-only `auth_session_id` cookie.
    pub auth_session_id: String,
}

/// Response of the login screen context API. Discriminated by the `result` tag.
///
/// Returns **only the display hints** the authorization request brought (no user, credentials or consent state).
/// `login_hint` is an arbitrary string specified by the RP and does not imply an existing account.
/// `client_name` / `tenant_name` are display names looked up from values registered in the IdP, not claims by the RP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAuthorizeLoginContextResponse {
    Ok {
        /// `login_hint` (for prefilling the login field; `None` if unspecified).
        login_hint: Option<String>,
        /// `ui_locales` (space-separated BCP47 tags; `None` if unspecified).
        ui_locales: Option<String>,
        /// This authorization request's `redirect_uri` (the one that exactly matched the registered value).
        ///
        /// **The source of the origins web allows in the CSP `form-action`.** Submitting the login form
        /// redirects straight to the RP when SSO and consent are in place. Chrome applies
        /// `form-action` to redirect targets after form submission too, so unless the RP's origin is
        /// allowed, that navigation is blocked (same situation as SAML's ACS; `handlers::saml_sso`).
        redirect_uri: Option<String>,
        /// Display name of the client that made the authorization request. Used in the login screen heading
        /// ("Sign in to ○○").
        ///
        /// **`Option` with `#[serde(default)]` for tolerance to deployment order**
        /// (same situation as `redirect_uri` of `InternalConsentInfoResponse::Ok`: during the few seconds api and web
        /// are swapped, "new web + old api" can occur). When `None`, the
        /// display name is not shown (= it just reverts to the heading before this screen changed).
        #[serde(default)]
        client_name: Option<String>,
        /// Display name of the flow's tenant. Shown in the login screen's navbar. When `None`, the default
        /// `IdP` is shown (`Option` for tolerance to deployment order, like `client_name`).
        #[serde(default)]
        tenant_name: Option<String>,
    },
    /// `auth_session_id` is invalid or expired (web continues rendering without context).
    SessionExpired,
    /// api internal error.
    Internal,
}

/// Request of the SAML SSO resume API (`POST /internal/saml/resume`).
///
/// api's `/{tenant_id}/saml/sso` validates the AuthnRequest and 302s to web's `/saml/continue`
/// with a single-use, short-lived handle (the same handoff as OIDC's `/authorize`; decision 2 of ADR-0018).
/// web passes the handle the first time, and `saml_request_id` (host-only cookie) when resuming after login, along with
/// the value of its own-domain `sso_session_id` cookie, to this API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalSamlResumeRequest {
    /// The flow's tenant (ADR-0009 §8). **Required**. api rejects a missing or invalid UUID with 400.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// The single-use handle `/saml/sso` put on the redirect URL (first time only).
    #[serde(default)]
    pub handle: Option<String>,
    /// Progress state id used to resume after login (value of web's host-only `saml_request_id` cookie).
    #[serde(default)]
    pub saml_request_id: Option<String>,
    /// Value of web's host-only `sso_session_id` cookie (`None` if absent = not logged in).
    #[serde(default)]
    pub sso_session_id: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the SAML SSO resume API. Discriminated by the `result` tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalSamlResumeResponse {
    /// SSO valid. web renders a form auto-POSTing `SAMLResponse` (already base64) and `relay_state` to `acs_url`,
    /// and expires the `saml_request_id` cookie.
    Completed {
        acs_url: String,
        saml_response: String,
        #[serde(default)]
        relay_state: Option<String>,
    },
    /// Authentication required. web turns `saml_request_id` into a host-only cookie and leads to the portal login.
    LoginRequired { saml_request_id: String },
    /// Authenticated, but use of this app is not permitted (ADR-0054). ⚠ **Does not POST to the ACS.**
    /// web refuses on the same screen as the OIDC path and expires the `saml_request_id` cookie (the progress state
    /// was already consumed on the api side).
    ApplicationNotPermitted { application_name: String },
    /// The handle or progress state is invalid, expired or used (start over from the SP).
    Expired,
    /// api internal error.
    Internal,
}

/// Request of the internal API for RP-initiated Logout (`POST /internal/logout/rp`, decision 2 of ADR-0018).
///
/// OIDC's `end_session_endpoint` is received by web (`GET /{tenant_id}/logout`), which forwards its own-domain
/// `sso_session_id` cookie and the query parameters to this API. api handles revoking the SSO session,
/// back-channel notification, and validating and building `post_logout_redirect_uri` (including adding `state`), while
/// **web discards the SSO cookie and renders the front-channel iframe page**.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalRpLogoutRequest {
    /// Tenant of the flow being logged out (ADR-0009 §8). **Required**. api rejects a missing or invalid UUID with 400.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Value of web's host-only `sso_session_id` cookie (`None` if absent = treated as already logged out).
    #[serde(default)]
    pub sso_session_id: Option<String>,
    /// `client_id` query (used to validate `post_logout_redirect_uri`; optional).
    #[serde(default)]
    pub client_id: Option<String>,
    /// `id_token_hint` query (OIDC RP-Initiated Logout 1.0 §2; G12). api verifies its signature and issuer,
    /// uses `aud` as the match target for `post_logout_redirect_uri`, and `sub` to confirm "whose logout
    /// it is". Accepted even if expired (the hint is an ID token issued in the past).
    #[serde(default)]
    pub id_token_hint: Option<String>,
    /// Post-logout redirect target specified by the RP (only registered ones are allowed).
    #[serde(default)]
    pub post_logout_redirect_uri: Option<String>,
    /// Random value the RP receives (transparently appended to the validated redirect URI).
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the internal API for RP-initiated Logout.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalRpLogoutResponse {
    /// Logout done (idempotently succeeds even if there was no session). web discards the SSO cookie and
    /// renders the iframe page if there are `frontchannel_uris`, otherwise 302s to `redirect_to`
    /// (if neither, shows the completion page).
    Ok {
        /// URIs loaded into the front-channel logout iframes (with the `iss` query added).
        frontchannel_uris: Vec<String>,
        /// Validated post-logout redirect target (with `state` added; `None` if unspecified or validation failed).
        redirect_to: Option<String>,
    },
    /// **Did nothing** because the user `id_token_hint` points to does not match the user of the session web
    /// forwarded (G12). web **must not delete the SSO cookie**: doing so would leave the session alive in the DB
    /// with no way back from the browser, ultimately breaking the login state of the other user it tried
    /// to protect. The screen conveys that "nothing was changed".
    SubjectMismatch,
    /// api internal error.
    Internal,
}

/// Request of the internal authentication API (`POST /internal/authenticate`).
///
/// web forwards credentials, the `auth_session_id` reference and client connection info (IP from `X-Forwarded-For`, User-Agent)
/// to api. CSRF is verified by api's LoginService using `csrf_token` (derived from `auth_session_id`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAuthenticateRequest {
    /// The flow's tenant (ADR-0009 §8). Authentication targets only ACTIVE members of that tenant (HOME
    /// members and GUESTs who joined by invitation), so authentication without a tenant cannot hold.
    /// **Required**. api rejects a missing or invalid UUID with 400 (fail-closed; SEC4).
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub auth_session_id: Option<String>,
    /// Login identifier (username = `preferred_username`; ADR-0009 §8). By default the same as the email
    /// (the email is used if unspecified at creation), but matching is against `preferred_username`.
    pub username: String,
    pub password: String,
    pub csrf_token: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the internal authentication API. Discriminated by the `result` tag. SSO/redirect info is returned only on success.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAuthenticateResponse {
    /// Authenticated and consented. 302 to `redirect_to` (RP URL with code) and turn `sso_session_id` into a cookie.
    Success {
        redirect_to: String,
        /// Hidden fields POSTed for `form_post` (G12). `None` means `query`.
        #[serde(default)]
        form_post: Option<FormPostFields>,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
        /// The user's display language setting (`ja` / `en`; MT20). None = unset.
        /// web overwrites the `lang` cookie with this value, realizing priority 2 (user setting).
        #[serde(default)]
        user_language: Option<String>,
    },
    /// Authenticated but consent required. Issue the `auth_session_id` cookie and 302 to `/consent`.
    /// `sso_session_id` is also issued (to set the SSO cookie).
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// Password authentication succeeded but MFA (TOTP) is configured. Leads to the TOTP input screen `/mfa/totp`.
    /// The `auth_session_id` cookie is kept as is (used for MFA verification).
    MfaRequired { auth_session_id: String },
    /// Password authentication succeeded but `must_change_password` (ADR-0009 §5). Leads to the password change screen.
    /// The `auth_session_id` cookie is kept as is (used for the change).
    PasswordChangeRequired { auth_session_id: String },
    /// Password authentication succeeded but the self-registered account's email is unverified (SEC6b). Login is not
    /// allowed until the confirmation link is followed. web shows a "check your email" notice.
    EmailVerificationRequired,
    /// Refused by an authentication policy (user authentication and authentication policy spec §7.4 `deny`).
    /// web shows that it was "refused by the organization's policy" (credentials are already verified, so there is no enumeration risk).
    PolicyDenied,
    /// Authenticated, but use of this app is not permitted (ADR-0054). ⚠ **Not returned to the RP.**
    /// web refuses on assay's screen: to the user it is "I got in and was then kicked out", so it shows the fact that
    /// authentication passed, the app name, and a way to ask the admin.
    ApplicationNotPermitted {
        application_name: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// An authentication policy required MFA, but there is no usable authenticator (confirmed TOTP).
    /// web guides the user to set up MFA from the portal.
    MfaEnrollmentRequired,
    /// No AuthSession, or expired (start over from `/authorize`).
    SessionExpired,
    /// CSRF token mismatch.
    CsrfMismatch,
    /// Per-IP rate limit exceeded.
    RateLimited,
    /// Invalid credentials.
    InvalidCredentials,
    /// Account is locked.
    Locked,
    /// api internal error.
    Internal,
    /// Authenticated, but on an unregistered device in an organization limited to registered devices (task #916, ADR-0079).
    /// No SSO cookie. web puts `ticket` in a cookie and sends the user to the device registration screen.
    DeviceEnrollmentRequired { ticket: String },
}

/// Request of the TOTP setup start API (`POST /internal/mfa/totp/setup`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalTotpSetupRequest {
    /// Raw value of the SSO session cookie (forwarded by web).
    ///
    /// The account label shown in the authenticator app is **looked up by the receiver (api) from this session's user**.
    /// web does not know the user name, so it used to pass an empty string here and the QR label came out empty.
    pub sso_session_id: String,
}

/// Response of the TOTP setup start API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalTotpSetupResponse {
    /// Setup started. Returns the QR URI and the raw secret (base32).
    Ok {
        /// `otpauth://totp/...` URI. Used to generate the QR code.
        totp_uri: String,
        /// base32-encoded secret. Shown directly to users who cannot use the QR.
        secret_base32: String,
    },
    /// A valid TOTP is already configured (cannot set up again; delete it first).
    AlreadyConfigured,
    /// No SSO session, or expired.
    SessionExpired,
    /// api internal error.
    Internal,
}

/// Request of the TOTP confirm API (`POST /internal/mfa/totp/confirm`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalTotpConfirmRequest {
    pub sso_session_id: String,
    /// 6-digit code the user entered from the authenticator app.
    pub code: String,
}

/// Response of the TOTP confirm API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalTotpConfirmResponse {
    Ok,
    InvalidCode,
    NotFound,
    AlreadyConfigured,
    SessionExpired,
    Internal,
}

/// Request of the TOTP delete API (`POST /internal/mfa/totp/delete`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalTotpDeleteRequest {
    pub sso_session_id: String,
}

/// Response of the TOTP delete API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalTotpDeleteResponse {
    Ok,
    SessionExpired,
    Internal,
}

/// Request of the login TOTP verification API (`POST /internal/mfa/totp/verify`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalVerifyTotpRequest {
    /// The flow's tenant (ADR-0009 §8). **Required**. api rejects a missing or invalid UUID with 400 (fail-closed; SEC4).
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub auth_session_id: Option<String>,
    pub totp_code: String,
    pub csrf_token: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the login TOTP verification API. The success variants are equivalent to `InternalAuthenticateResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalVerifyTotpResponse {
    Success {
        redirect_to: String,
        /// Hidden fields POSTed for `form_post` (G12). `None` means `query`.
        #[serde(default)]
        form_post: Option<FormPostFields>,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
        /// The user's display language setting (MT20). web overwrites the `lang` cookie with this value.
        #[serde(default)]
        user_language: Option<String>,
    },
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    SessionExpired,
    CsrfMismatch,
    InvalidCode,
    /// Hit the per-IP rate limit (SEC3).
    RateLimited,
    /// The account is locked (by consecutive TOTP failures, or failures on the password side; SEC3).
    Locked,
    /// Refused by an authentication policy (AP2/AP3). Even after passing the second factor, this is reached when it changed to `deny`
    /// or the method did not satisfy `require_specific_method`.
    PolicyDenied,
    /// Authenticated, but use of this app is not permitted (ADR-0054). ⚠ **Not returned to the RP.**
    /// web refuses on assay's screen: to the user it is "I got in and was then kicked out", so it shows the fact that
    /// authentication passed, the app name, and a way to ask the admin.
    ApplicationNotPermitted {
        application_name: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    Internal,
    /// Authenticated, but on an unregistered device in an organization limited to registered devices (task #916, ADR-0079).
    /// No SSO cookie. web puts `ticket` in a cookie and sends the user to the device registration screen.
    DeviceEnrollmentRequired {
        ticket: String,
    },
}

/// Request of the password change API (`POST /internal/change-password`, ADR-0009 §5).
///
/// In response to `must_change_password` detected by `LoginService`, sets a new password with the in-login `auth_session_id`
/// (password-verified state). Since the flow is "a logged-in user authenticates with the current password and then
/// sets a new password", the current password is included.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalChangePasswordRequest {
    /// The flow's tenant (ADR-0009 §8). **Required**. api rejects a missing or invalid UUID with 400 (fail-closed; SEC4).
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub auth_session_id: Option<String>,
    pub current_password: String,
    pub new_password: String,
    pub csrf_token: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Why a new password was not accepted (AP7).
///
/// It is not lumped into the single word "weak" because the user's next action differs by reason
/// (too short can be lengthened, but breached or reused means **thinking of a different value**). web maps this value
/// to the screen's message key.
///
/// The default is `Policy` (length etc.). Reading an old response without a reason shows the same as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordRejectionReason {
    /// Does not meet requirements on the input itself, such as length.
    #[default]
    Policy,
    /// A known breached password.
    Breached,
    /// Reuse of the current or a previously used password.
    Reused,
}

/// Response of the password change API. The success variants are equivalent to `InternalAuthenticateResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalChangePasswordResponse {
    Success {
        redirect_to: String,
        /// Hidden fields POSTed for `form_post` (G12). `None` means `query`.
        #[serde(default)]
        form_post: Option<FormPostFields>,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// Changed, but an authentication policy requires MFA and TOTP is configured. Keeps the `auth_session_id` cookie and
    /// leads to the TOTP input screen `/mfa/totp` (SSO is not issued yet).
    MfaRequired {
        auth_session_id: String,
    },
    /// Changed, but login was refused by an authentication policy (spec §7.4 `deny`).
    PolicyDenied,
    /// Authenticated, but use of this app is not permitted (ADR-0054). ⚠ **Not returned to the RP.**
    /// web refuses on assay's screen: to the user it is "I got in and was then kicked out", so it shows the fact that
    /// authentication passed, the app name, and a way to ask the admin.
    ApplicationNotPermitted {
        application_name: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// Changed, but an authentication policy requires MFA and there is no usable authenticator (confirmed TOTP).
    /// web guides the user to set up MFA from the portal.
    MfaEnrollmentRequired,
    SessionExpired,
    CsrfMismatch,
    /// The current password does not match.
    InvalidCurrentPassword,
    /// The new password does not satisfy the policy (length, breached, reused).
    WeakPassword {
        #[serde(default)]
        reason: PasswordRejectionReason,
    },
    Internal,
    /// Authenticated, but on an unregistered device in an organization limited to registered devices (task #916, ADR-0079).
    /// No SSO cookie. web puts `ticket` in a cookie and sends the user to the device registration screen.
    DeviceEnrollmentRequired {
        ticket: String,
    },
}

/// Request of the self-service password change API (`POST /internal/account/change-password`, MT15).
///
/// Separate from the forced change during the login flow ([`InternalChangePasswordRequest`], `auth_session` based),
/// this is the route where **a logged-in user with an SSO session** changes their own password from the settings screen.
/// web forwards the raw SSO cookie value, and api resolves the user and re-verifies the current password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountChangePasswordRequest {
    /// Raw value of the SSO session cookie.
    pub sso_session_id: String,
    pub current_password: String,
    pub new_password: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the self-service password change API. Not an OIDC flow, so no redirect/code is returned.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountChangePasswordResponse {
    Ok,
    /// No SSO session, or expired (treated as logged out).
    SessionExpired,
    /// The current password does not match.
    InvalidCurrentPassword,
    /// The new password does not satisfy the policy (length, breached, reused).
    WeakPassword {
        #[serde(default)]
        reason: PasswordRejectionReason,
    },
    Internal,
}

/// Request of the password reset request API (`POST /internal/password-reset/request`; MT18).
/// An unauthenticated path, so no SSO is needed. web's CSRF does not depend on a form session, so api does not verify it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPasswordResetRequestRequest {
    /// Tenant of the login screen (ADR-0009 §8). **Required**. api rejects a missing or invalid UUID with 400.
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub email: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the password reset request API. Does not branch on whether the account exists (anti-enumeration; MT18).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPasswordResetRequestResponse {
    /// Accepted (an email was sent if the account exists).
    Accepted,
    /// SMTP is not configured, so the feature itself is unavailable (account-independent).
    Unavailable,
    RateLimited,
}

/// Request of the password reset completion API (`POST /internal/password-reset/complete`; MT18).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPasswordResetCompleteRequest {
    /// Tenant of the reset screen. **Required** (fails unless it matches the token owner's home tenant).
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Plain token received via the email link.
    pub token: String,
    pub new_password: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the password reset completion API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPasswordResetCompleteResponse {
    Ok,
    /// The token is invalid, expired, used, or for another tenant.
    InvalidOrExpired,
    /// The new password does not satisfy the policy (length, breached, reused).
    WeakPassword {
        #[serde(default)]
        reason: PasswordRejectionReason,
    },
    Internal,
}

/// Request of the API reading the content of an account setup link (`POST /internal/account-setup/describe`; ADR-0062).
/// ⚠ **Only reads; does not consume** (so a preview bot does not eat it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountSetupDescribeRequest {
    /// The link's tenant. **Required** (fails unless it matches the token owner's home tenant).
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Plain token received via the link.
    pub token: String,
}

/// Content of an account setup link.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountSetupDescribeResponse {
    Ok {
        /// Whose link it is (shown on screen; visible only to the link holder).
        email: String,
        /// Whether a passkey may be registered on this screen (true only for `setup` links; ADR-0062).
        allows_passkey: bool,
        /// The link's expiry time (RFC3339).
        expires_at: String,
    },
    /// Nonexistent, expired, used, or another tenant. **Not distinguished**.
    InvalidOrExpired,
    Internal,
}

/// Start of passkey registration from a setup link (`POST /internal/account-setup/passkey/begin`; ADR-0062).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountSetupPasskeyBeginRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub token: String,
}

/// Response of starting passkey registration from a setup link.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountSetupPasskeyBeginResponse {
    Ok {
        /// Temporary ID returned in complete.
        challenge_id: String,
        /// JSON passed to the browser's `navigator.credentials.create()`.
        options: serde_json::Value,
    },
    InvalidOrExpired,
    /// Links of this purpose do not allow registration.
    NotAllowed,
    Internal,
}

/// Completion of passkey registration from a setup link (`POST /internal/account-setup/passkey/complete`; ADR-0062).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountSetupPasskeyCompleteRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub token: String,
    pub challenge_id: String,
    /// Name given to the authenticator (typed on screen; a default is used if empty).
    pub name: String,
    /// Public key credential returned by the browser.
    pub credential: serde_json::Value,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of completing passkey registration from a setup link.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountSetupPasskeyCompleteResponse {
    Ok,
    InvalidOrExpired,
    NotAllowed,
    /// The value returned by the authenticator could not be accepted.
    InvalidCredential,
    Internal,
}

/// Request of the admin console internal authentication API (`POST /internal/authenticate/admin`, ADR-0007 §3, §4).
///
/// CSRF of admin login is already verified on the web side (ADR-0007 §4), so it is not included in this API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAdminAuthenticateRequest {
    /// Tenant of the admin login (ADR-0009 §8). **Required**. api rejects a missing or invalid UUID with 400 (fail-closed; SEC4).
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Login identifier (username = `preferred_username`; ADR-0009 §8).
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Request of the internal logout API (`POST /internal/logout`, ADR-0007).
///
/// On admin console logout, web forwards the SSO session id to revoke (cookie value) and the client connection info.
/// web expires the cookie; api deletes the session from the DB and records the audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalLogoutRequest {
    /// Tenant of the flow being logged out (ADR-0009 §8). **Required**. api rejects a missing or invalid UUID with 400 (fail-closed; SEC4).
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the admin console internal authentication API. On success returns the SSO session id (no code/redirect).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAdminAuthenticateResponse {
    /// Authenticated and holds `idp.tenant.admin`. Turn `sso_session_id` into a cookie and 302 to the admin console.
    Success {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// Per-IP rate limit exceeded.
    RateLimited,
    /// Invalid credentials.
    InvalidCredentials,
    /// Account is locked.
    Locked,
    /// Credentials are correct but no tenant admin permission is held.
    Forbidden,
    /// Authenticated and holds admin permission, but `must_change_password` (ADR-0009 §5). Leads to the password change screen.
    /// `username` returns the input as is for redisplaying the form. SSO is not issued yet.
    PasswordChangeRequired { username: String },
    /// Refused by an authentication policy (AP2; user authentication and authentication policy spec §7.4 `deny`).
    PolicyDenied,
    /// An authentication policy required MFA, but there is no usable authenticator (confirmed TOTP) (AP2).
    MfaEnrollmentRequired,
    /// An authentication policy requires MFA and an authenticator is registered (AP2). Admin console login has no
    /// second-factor input step, so it guides the user to pass MFA via portal login before entering.
    MfaRequired,
    /// api internal error.
    Internal,
    /// Authenticated, but on an unregistered device in an organization limited to registered devices (task #916, ADR-0079).
    /// No SSO cookie. web puts `ticket` in a cookie and sends the user to the device registration screen.
    DeviceEnrollmentRequired { ticket: String },
}

/// Request of the admin console forced password change API (`POST /internal/authenticate/admin/change-password`,
/// ADR-0009 §5). Admin login has no temporary state like `auth_session_id`, so everything,
/// including the current password, is fully re-verified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAdminChangePasswordRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Login identifier (username = `preferred_username`; ADR-0009 §8).
    pub username: String,
    pub current_password: String,
    pub new_password: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the admin console forced password change API. On success it is equivalent to `InternalAdminAuthenticateResponse`
/// (returns the SSO session id).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAdminChangePasswordResponse {
    Success {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    RateLimited,
    InvalidCredentials,
    Locked,
    Forbidden,
    /// The new password does not satisfy the policy (length, breached, reused).
    WeakPassword {
        #[serde(default)]
        reason: PasswordRejectionReason,
    },
    /// Changed, but refused by an authentication policy (AP2).
    PolicyDenied,
    /// Changed, but an authentication policy requires MFA and there is no usable authenticator (AP2).
    MfaEnrollmentRequired,
    /// Changed, but an authentication policy requires MFA (an authenticator is registered; AP2).
    MfaRequired,
    Internal,
    /// Authenticated, but on an unregistered device in an organization limited to registered devices (task #916, ADR-0079).
    /// No SSO cookie. web puts `ticket` in a cookie and sends the user to the device registration screen.
    DeviceEnrollmentRequired {
        ticket: String,
    },
}

/// Request of the end-user portal internal authentication API (`POST /internal/authenticate/portal`).
///
/// Same shape as the admin console's [`InternalAdminAuthenticateRequest`]. The portal is a direct login into the IdP's own
/// account screen (`/{tenant_id}/settings`) without an OIDC client (RP), and on success it issues an SSO session directly
/// without issuing an authorization code. CSRF is already verified on the web side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPortalAuthenticateRequest {
    /// Tenant of the login (ADR-0009 §8). **Required**. api rejects a missing or invalid UUID with 400.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Login identifier (username = `preferred_username`; ADR-0009 §8).
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the portal internal authentication API. On success returns the SSO session id (no code/redirect).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPortalAuthenticateResponse {
    /// Authenticated (TOTP not configured). Turn `sso_session_id` into a cookie and 302 to the account screen.
    Success {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
        #[serde(default)]
        user_language: Option<String>,
    },
    /// Password authentication succeeded but TOTP is required. `mfa_ticket` is a signed short-lived ticket (user_id + expiry),
    /// which web turns into a cookie and leads to the TOTP input screen. SSO is not issued yet.
    MfaRequired { mfa_ticket: String },
    /// The self-registered account's email is unverified (SEC6b). Guides the user to follow the confirmation link.
    EmailVerificationRequired,
    /// A forced password change is required (ADR-0009 §5). web leads to the forced password change form
    /// (same approach as the admin console; `username` returns the input as is for redisplaying the form).
    PasswordChangeRequired { username: String },
    /// Refused by an authentication policy (AP2; spec §7.4 `deny`).
    PolicyDenied,
    /// An authentication policy required MFA, but there is no usable authenticator (confirmed TOTP) (AP2).
    MfaEnrollmentRequired,
    /// Per-IP rate limit exceeded.
    RateLimited,
    /// Invalid credentials.
    InvalidCredentials,
    /// Account is locked.
    Locked,
    /// api internal error.
    Internal,
    /// Authenticated, but on an unregistered device in an organization limited to registered devices (task #916, ADR-0079).
    /// No SSO cookie. web puts `ticket` in a cookie and sends the user to the device registration screen.
    DeviceEnrollmentRequired { ticket: String },
}

/// Request of the portal forced password change API (`POST /internal/authenticate/portal/change-password`,
/// ADR-0009 §5). Portal login has no temporary state like `auth_session_id`, so,
/// like the admin console, everything including the current password is fully re-verified (admin permission is not required).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPortalChangePasswordRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Login identifier (username = `preferred_username`).
    pub username: String,
    pub current_password: String,
    pub new_password: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the portal forced password change API. On success returns the SSO session id
/// (no code/redirect, as with `InternalPortalAuthenticateResponse::Success`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPortalChangePasswordResponse {
    Success {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
        #[serde(default)]
        user_language: Option<String>,
    },
    /// Password changed but TOTP is required (the same MFA gate as `login()`). Turn `mfa_ticket` into a cookie and
    /// lead to the TOTP input screen. SSO is not issued yet.
    MfaRequired {
        mfa_ticket: String,
    },
    /// The self-registered account's email is unverified (SEC6b). Guides the user to follow the confirmation link.
    EmailVerificationRequired,
    /// Changed, but refused by an authentication policy (AP2).
    PolicyDenied,
    /// Changed, but an authentication policy requires MFA and there is no usable authenticator (AP2).
    MfaEnrollmentRequired,
    RateLimited,
    /// Invalid credentials (missing user, current password mismatch, disabled account etc. are not distinguished).
    InvalidCredentials,
    Locked,
    /// The new password does not satisfy the policy (length, breached, reused).
    WeakPassword {
        #[serde(default)]
        reason: PasswordRejectionReason,
    },
    Internal,
    /// Authenticated, but on an unregistered device in an organization limited to registered devices (task #916, ADR-0079).
    /// No SSO cookie. web puts `ticket` in a cookie and sends the user to the device registration screen.
    DeviceEnrollmentRequired {
        ticket: String,
    },
}

/// Request of the portal TOTP verification API (`POST /internal/authenticate/portal/mfa`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPortalMfaRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// The signed ticket returned in [`InternalPortalAuthenticateResponse::MfaRequired`].
    pub mfa_ticket: String,
    pub totp_code: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the portal TOTP verification API. On success returns the SSO session id.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPortalMfaResponse {
    Success {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
        #[serde(default)]
        user_language: Option<String>,
    },
    /// Invalid TOTP code (can retry if the ticket is valid).
    InvalidCode,
    /// The ticket is invalid or expired (start over from login).
    TicketExpired,
    /// Refused by an authentication policy (AP2; when the policy changed after the ticket was issued).
    PolicyDenied,
    /// Per-IP rate limit exceeded.
    RateLimited,
    /// api internal error.
    Internal,
    /// Authenticated, but on an unregistered device in an organization limited to registered devices (task #916, ADR-0079).
    /// No SSO cookie. web puts `ticket` in a cookie and sends the user to the device registration screen.
    DeviceEnrollmentRequired { ticket: String },
}

/// Request of the consent screen info API (`GET /internal/consent-info`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalConsentInfoRequest {
    /// The flow's tenant (ADR-0009 §8). **Required**. api rejects a missing or invalid UUID with 400 (fail-closed; SEC4).
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub auth_session_id: String,
}

/// Response of the consent screen info API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalConsentInfoResponse {
    /// The session is valid. Returns the information needed for the consent screen.
    Ok {
        auth_session_id: String,
        client_name: String,
        client_id: String,
        /// Scopes consent is asked for (excluding `openid`).
        requested_scopes: Vec<String>,
        /// This authorization request's `redirect_uri` (the one that exactly matched the registered value).
        ///
        /// **The source of the origins web allows in the CSP `form-action`.** Submitting the consent form
        /// ends in a redirect to the RP, and Chrome applies `form-action` to redirect targets after form submission
        /// too. Without allowing it, consent is recorded and a code is issued, yet the browser cannot return to the RP.
        ///
        /// **It is `Option` for tolerance to deployment order.** api and web are separate containers, and during the few
        /// seconds of swapping, "new web + old api" can occur. If required, deserializing this response would fail in that
        /// window and **the whole consent screen would go down**. When `None`, no allowance is added (= it merely reverts to
        /// the state before this bug was fixed). The sibling `InternalAuthorizeLoginContextResponse::Ok` is the same.
        #[serde(default)]
        redirect_uri: Option<String>,
    },
    /// No AuthSession, expired, or no authenticated user set (start over from `/authorize`).
    SessionExpired,
}

/// Request of the consent approval API (`POST /internal/consent/approve`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalConsentApproveRequest {
    /// The flow's tenant (ADR-0009 §8). **Required**. api rejects a missing or invalid UUID with 400 (fail-closed; SEC4).
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub auth_session_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the consent approval API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalConsentApproveResponse {
    /// Consent granted and code issued. 302 to `redirect_to` (RP URL with code).
    Success {
        redirect_to: String,
        /// Hidden fields POSTed for `form_post` (G12). `None` means `query`.
        #[serde(default)]
        form_post: Option<FormPostFields>,
    },
    /// Authenticated, but use of this app is not permitted (ADR-0054). ⚠ **Not returned to the RP.**
    /// web refuses on assay's screen: to the user it is "I got in and was then kicked out", so it shows the fact that
    /// authentication passed, the app name, and a way to ask the admin.
    ApplicationNotPermitted { application_name: String },
    /// No AuthSession, or expired.
    SessionExpired,
    /// api internal error.
    Internal,
}

/// Request of the consent denial API (`POST /internal/consent/deny`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalConsentDenyRequest {
    /// The flow's tenant (ADR-0009 §8). **Required**. api rejects a missing or invalid UUID with 400 (fail-closed; SEC4).
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub auth_session_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the consent denial API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalConsentDenyResponse {
    /// Denial done. 302 to `redirect_to` (RP URL with the `access_denied` error).
    Ok {
        redirect_to: String,
        /// Hidden fields POSTed for `form_post` (G12). `None` means `query`.
        /// Errors are returned in the same `response_mode` as success (the RP waits at the same endpoint).
        #[serde(default)]
        form_post: Option<FormPostFields>,
    },
    /// No AuthSession, or expired (cannot redirect to the RP).
    SessionExpired,
    /// api internal error.
    Internal,
}

// ─── Passkey (WebAuthn) registration API ─────────────────────────────────────────────

/// Request of the passkey registration start API (`POST /internal/passkey/register/begin`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPasskeyRegisterBeginRequest {
    /// Raw value of the SSO session cookie.
    pub sso_session_id: String,
    /// User name shown on the authenticator (usually the email).
    pub user_name: String,
}

/// Response of the passkey registration start API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPasskeyRegisterBeginResponse {
    /// Started. Use `challenge_id` in complete. Pass `options` to the JS WebAuthn API.
    Ok {
        challenge_id: String,
        options: serde_json::Value,
    },
    /// No SSO session, or expired.
    SessionExpired,
    /// api internal error.
    Internal,
}

/// Request of the passkey registration completion API (`POST /internal/passkey/register/complete`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPasskeyRegisterCompleteRequest {
    pub sso_session_id: String,
    pub challenge_id: String,
    /// Device name given by the user (e.g. "MacBook Touch ID").
    pub name: String,
    /// Object (JSON) returned by the browser's `navigator.credentials.create()`.
    pub credential: serde_json::Value,
}

/// Response of the passkey registration completion API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPasskeyRegisterCompleteResponse {
    /// Registered. `credential_id` is for display on the admin screen.
    Ok { credential_id: String },
    /// The challenge was not found or expired.
    ChallengeNotFound,
    /// The credential is invalid.
    InvalidCredential,
    /// The same device is already registered.
    DuplicateCredential,
    /// No SSO session, or expired.
    SessionExpired,
    /// api internal error.
    Internal,
}

/// Request of the passkey delete API (`POST /internal/passkey/delete`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPasskeyDeleteRequest {
    pub sso_session_id: String,
    /// Internal UUID to delete (`InternalPasskeyRegisterCompleteResponse::Ok.credential_id`).
    pub credential_id: String,
}

/// Response of the passkey delete API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPasskeyDeleteResponse {
    Ok,
    /// Not found as a usable passkey of that user (already gone, someone else's id, a broken id).
    /// The screen must not say "deleted", so it is returned distinct from success.
    NotFound,
    SessionExpired,
    Internal,
}

/// Request of the passkey list API (`POST /internal/passkey/list`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPasskeyListRequest {
    pub sso_session_id: String,
}

/// Summary of a registered credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredentialInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    /// Suspended in the authenticator registry (AP9). **It appears in the list, but cannot be used to sign in.**
    /// Unless the screen shows this, the user would look at an unusable passkey as if it were usable
    /// (suspension is applied and lifted from `/{tenant_id}/settings/authenticators`).
    #[serde(default)]
    pub suspended: bool,
}

/// Response of the passkey list API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPasskeyListResponse {
    Ok {
        credentials: Vec<PasskeyCredentialInfo>,
    },
    SessionExpired,
    Internal,
}

// ─── Passkey (WebAuthn) authentication API ─────────────────────────────────────────────

/// Request of the passkey authentication start API (`POST /internal/passkey/login/begin`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPasskeyLoginBeginRequest {
    /// auth_session_id (cookie value) of the OIDC flow. Needed to continue the OIDC flow in complete.
    ///
    /// **`None` makes a challenge for direct login outside the authorization flow** (admin console, portal).
    /// The challenge's purpose is decided by its presence, and the completion APIs do not accept a challenge of another purpose.
    pub auth_session_id: Option<String>,
}

/// Response of the passkey authentication start API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPasskeyLoginBeginResponse {
    /// Started. Use `challenge_id` in complete. Pass `options` to the JS WebAuthn API.
    Ok {
        challenge_id: String,
        options: serde_json::Value,
    },
    /// api internal error.
    Internal,
}

/// Request of the passkey authentication completion API (`POST /internal/passkey/login/complete`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPasskeyLoginCompleteRequest {
    /// The flow's tenant (ADR-0009 §8). **Required**. api rejects a missing or invalid UUID with 400 (fail-closed; SEC4).
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub challenge_id: String,
    /// Object (JSON) returned by the browser's `navigator.credentials.get()`.
    pub credential: serde_json::Value,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the passkey authentication completion API. The success variants are equivalent to `InternalAuthenticateResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPasskeyLoginCompleteResponse {
    Success {
        redirect_to: String,
        /// Hidden fields POSTed for `form_post` (G12). `None` means `query`.
        #[serde(default)]
        form_post: Option<FormPostFields>,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// The challenge was not found or expired.
    ChallengeNotFound,
    /// No AuthSession, or expired.
    SessionExpired,
    /// The credential is invalid.
    InvalidCredential,
    /// Refused by an authentication policy (user authentication and authentication policy spec §7.4 `deny`).
    PolicyDenied,
    /// Authenticated, but use of this app is not permitted (ADR-0054). ⚠ **Not returned to the RP.**
    /// web refuses on assay's screen: to the user it is "I got in and was then kicked out", so it shows the fact that
    /// authentication passed, the app name, and a way to ask the admin.
    ApplicationNotPermitted {
        application_name: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// Per-IP rate limit exceeded. Consumes the same bucket as the direct login passkey path.
    RateLimited,
    /// api internal error.
    Internal,
    /// Authenticated, but on an unregistered device in an organization limited to registered devices (task #916, ADR-0079).
    /// No SSO cookie. web puts `ticket` in a cookie and sends the user to the device registration screen.
    DeviceEnrollmentRequired { ticket: String },
}

/// Request of the admin console passkey login completion API (`POST /internal/passkey/login/admin/complete`).
/// The start calls `POST /internal/passkey/login/begin`, shared by the 3 paths, without `auth_session_id`
/// (= a challenge for direct login).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAdminPasskeyLoginCompleteRequest {
    /// Tenant to log in to (ADR-0009 §8). **Required**. api rejects a missing or invalid UUID with 400.
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub challenge_id: String,
    /// Object (JSON) returned by the browser's `navigator.credentials.get()`.
    pub credential: serde_json::Value,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the admin console passkey login completion API.
///
/// `Locked` / `PasswordChangeRequired` / `MfaRequired` / `MfaEnrollmentRequired`, present in the password path
/// (`InternalAdminAuthenticateResponse`), are absent here, because a passkey uses no password
/// and satisfies `require_mfa` on its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAdminPasskeyLoginCompleteResponse {
    /// Authenticated and holds tenant admin permission. Turn `sso_session_id` into a cookie and go to the admin console.
    Success {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// The challenge was not found, expired, or is for another purpose. Prompts a retry.
    ChallengeNotFound,
    /// The credential is invalid (nonexistent, verification failed, suspended, not in the tenant, account disabled).
    InvalidCredential,
    /// The passkey is correct but no tenant admin permission is held.
    Forbidden,
    /// Refused by an authentication policy (AP2; spec §7.4 `deny`).
    PolicyDenied,
    /// Per-IP rate limit exceeded.
    RateLimited,
    /// api internal error.
    Internal,
    /// Authenticated, but on an unregistered device in an organization limited to registered devices (task #916, ADR-0079).
    /// No SSO cookie. web puts `ticket` in a cookie and sends the user to the device registration screen.
    DeviceEnrollmentRequired { ticket: String },
}

/// Request of the portal passkey login completion API (`POST /internal/passkey/login/portal/complete`).
/// The start calls `POST /internal/passkey/login/begin`, shared by the 3 paths, without `auth_session_id`
/// (= a challenge for direct login).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPortalPasskeyLoginCompleteRequest {
    /// Tenant to log in to (ADR-0009 §8). **Required**. api rejects a missing or invalid UUID with 400.
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub challenge_id: String,
    /// Object (JSON) returned by the browser's `navigator.credentials.get()`.
    pub credential: serde_json::Value,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the portal passkey login completion API.
///
/// `MfaRequired` / `MfaEnrollmentRequired` / `Locked` / `PasswordChangeRequired`, present in the password path
/// (`InternalPortalAuthenticateResponse`), are absent here (a passkey satisfies `require_mfa` on its own and
/// uses no password). The unverified email gate remains.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPortalPasskeyLoginCompleteResponse {
    /// Authenticated. Turn `sso_session_id` into a cookie and go to the account screen.
    Success {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
        #[serde(default)]
        user_language: Option<String>,
    },
    /// The challenge was not found, expired, or is for another purpose. Prompts a retry.
    ChallengeNotFound,
    /// The credential is invalid (nonexistent, verification failed, suspended, not in the tenant, account disabled).
    InvalidCredential,
    /// The self-registered account's email is unverified (SEC6b). Guides the user to follow the confirmation link.
    EmailVerificationRequired,
    /// Refused by an authentication policy (AP2; spec §7.4 `deny`).
    PolicyDenied,
    /// Per-IP rate limit exceeded.
    RateLimited,
    /// api internal error.
    Internal,
    /// Authenticated, but on an unregistered device in an organization limited to registered devices (task #916, ADR-0079).
    /// No SSO cookie. web puts `ticket` in a cookie and sends the user to the device registration screen.
    DeviceEnrollmentRequired { ticket: String },
}

/// Request of the self-service display language update API (`POST /internal/account/update-language`; MT20).
///
/// When the language is changed on web's settings screen, updates `users.language` in the DB. web updates the cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountUpdateLanguageRequest {
    /// Raw value of the SSO session cookie (forwarded by web).
    pub sso_session_id: String,
    /// Language code to set (`ja` or `en`).
    pub language: String,
}

/// Response of the self-service display language update API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountUpdateLanguageResponse {
    Ok,
    /// No SSO session, or expired.
    SessionExpired,
    /// The given language code is unsupported (anything other than `ja` and `en`).
    InvalidLanguage,
    /// api internal error.
    Internal,
}

/// Request of the self-service color scheme update API (`POST /internal/account/update-theme`).
///
/// A logged-in user updates their own `users.theme` via the SSO session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountUpdateThemeRequest {
    /// Raw value of the SSO session cookie (forwarded by web).
    pub sso_session_id: String,
    /// Color scheme to set (`light` / `dark` / `system`).
    pub theme: String,
}

/// Response of the self-service color scheme update API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountUpdateThemeResponse {
    Ok,
    /// No SSO session, or expired.
    SessionExpired,
    /// The given color scheme is unsupported.
    InvalidTheme,
    /// api internal error.
    Internal,
}

/// Request of the self-service profile API (`POST /internal/account/profile`).
///
/// Fetches the user's own profile via the SSO session so the settings screen can redisplay (prefill) the current
/// display name etc. Read-only with no side effects (POST because the SSO is forwarded in the body).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountProfileRequest {
    /// Raw value of the SSO session cookie (forwarded by web).
    pub sso_session_id: String,
}

/// Response of the self-service profile API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountProfileResponse {
    Ok {
        /// Display name (`None` if unset).
        name: Option<String>,
        /// Login identifier (`None` if unset). Display only; cannot be changed.
        preferred_username: Option<String>,
        /// Email address.
        email: String,
        /// Saved display language (`ja` / `en`; `None` if unset). Takes priority over the cookie in web's display
        /// language decision (MT20; priority 2 in `CLAUDE.md` "Internationalization").
        #[serde(default)]
        language: Option<String>,
        /// Saved color scheme (`light` / `dark` / `system`; `None` if unset). Like the language, it takes
        /// priority over the cookie. `#[serde(default)]` so decoding does not fail when mixed with an old api.
        #[serde(default)]
        theme: Option<String>,
    },
    /// No SSO session, or expired.
    SessionExpired,
    /// api internal error.
    Internal,
}

/// Request of the self-service display name update API (`POST /internal/account/update-name`).
///
/// A logged-in user updates their own `users.name` (display name) via the SSO session.
/// When `name` is empty, whitespace-only or `None`, the display name is cleared (DB `NULL`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountUpdateNameRequest {
    /// Raw value of the SSO session cookie (forwarded by web).
    pub sso_session_id: String,
    /// New display name. Empty, whitespace-only or unspecified clears it.
    #[serde(default)]
    pub name: Option<String>,
}

/// Response of the self-service display name update API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountUpdateNameResponse {
    Ok,
    /// No SSO session, or expired.
    SessionExpired,
    /// The value is invalid, e.g. the display name is too long.
    Invalid,
    /// api internal error.
    Internal,
}

/// Summary of one switchable tenant (for the tenant switcher UI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountTenantSummary {
    /// Internal ID of the tenant (used in the URL prefix).
    pub tenant_id: String,
    /// Tenant display name.
    pub name: String,
    /// Membership kind (`HOME` / `GUEST`).
    pub membership_type: String,
}

/// Request of the self-service tenant list API (`POST /internal/account/tenants`).
///
/// Lists tenants where the logged-in user has an `ACTIVE` membership (for tenant switching).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountTenantsRequest {
    /// Raw value of the SSO session cookie (forwarded by web).
    pub sso_session_id: String,
}

/// Response of the self-service tenant list API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountTenantsResponse {
    Ok {
        tenants: Vec<AccountTenantSummary>,
    },
    /// No SSO session, or expired.
    SessionExpired,
    /// api internal error.
    Internal,
}

// ── Self-service security screen (G10) ──────────────────────────────────

/// Summary of one signed-in session (security screen).
///
/// `id` is a display ID used to reference it in revocation requests. It is neither the SSO cookie value nor the DB
/// primary key (`session_hash`) but an irreversible derivation of it, so presenting it gives no means to resolve or impersonate another person's session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSessionSummary {
    pub id: String,
    /// Whether this is the session used by this browser now (shown on screen as "current session").
    pub current: bool,
    /// Authentication time (RFC 3339).
    pub auth_time: String,
    /// Whether the second factor was completed (recorded by AP4).
    pub multi_factor: bool,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    pub created_at: String,
    /// Idle expiry time (RFC 3339).
    pub idle_expires_at: String,
    /// Absolute expiry (RFC 3339).
    pub absolute_expires_at: String,
}

/// Summary of one connected app (security screen).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountConnectedAppSummary {
    pub client_id: String,
    /// Display name (the same value as `client_id` if the client was deleted).
    pub app_name: String,
    pub scopes: Vec<String>,
    pub granted_at: String,
    pub updated_at: String,
}

/// Request of the API binding the logged-in device (`POST /internal/devices/observe`; task #872).
///
/// web calls it with the very response that sets the SSO session cookie. No tenant is needed (decided by the user's home tenant).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalDeviceObserveRequest {
    /// Value of the SSO session cookie web just set.
    pub sso_session_id: String,
    /// Device mark (web's cookie). `None` if it could not be set.
    #[serde(default)]
    pub device_token: Option<String>,
    /// `CF-IPCountry` (only when web decided to trust it via `TRUST_FORWARDED_HEADERS`).
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the API binding the logged-in device.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalDeviceObserveResponse {
    Registered,
    Unregistered,
    Ignored,
    Internal,
}

/// One row of the "devices" section. Times are RFC 3339.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountDeviceSummary {
    pub id: String,
    pub name: String,
    /// Whether this is the browser being viewed now.
    pub current: bool,
    #[serde(default)]
    pub user_agent: Option<String>,
    pub registered_at: String,
    pub last_used_at: String,
    #[serde(default)]
    pub last_country: Option<String>,
    /// Time the registration expires if it goes unused.
    pub expires_at: String,
}

/// Request of the API fetching the "devices" section (`POST /internal/account/devices`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountDevicesRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    #[serde(default)]
    pub device_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountDevicesResponse {
    Ok {
        devices: Vec<AccountDeviceSummary>,
        /// Whether the browser being viewed now is registered.
        current_registered: bool,
        /// Whether the browser being viewed now has a device mark (it cannot be registered without one).
        current_identified: bool,
        /// Whether identity confirmation by passkey is still valid.
        passkey_fresh: bool,
        /// Whether the "unregistered device" notice is enabled in this organization.
        alerts_enabled: bool,
    },
    SessionExpired,
    Internal,
}

/// Request of the device registration API (`POST /internal/account/devices/register`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountRegisterDeviceRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    #[serde(default)]
    pub device_token: Option<String>,
    pub name: String,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountRegisterDeviceResponse {
    Registered,
    /// More than 5 minutes have passed since identity confirmation by passkey. web sends the user to passkey confirmation.
    PasskeyRequired,
    AlreadyRegistered,
    InvalidName,
    DeviceUnidentified,
    SessionExpired,
    Internal,
}

/// Request of the device revocation API (`POST /internal/account/devices/revoke`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountRevokeDeviceRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    pub device_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountRevokeDeviceResponse {
    Revoked { sessions: usize },
    NotFound,
    SessionExpired,
    Internal,
}

/// One row of the "SSH keys" section (task #885). Times are RFC 3339.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSshKeySummary {
    pub id: String,
    pub name: String,
    /// Key type (`sk-ssh-ed25519@openssh.com` etc.).
    pub key_type: String,
    /// `SHA256:…`.
    pub fingerprint: String,
    pub created_at: String,
}

/// Request of the API fetching the "SSH keys" section (`POST /internal/account/ssh-keys`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountSshKeysRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountSshKeysResponse {
    Ok {
        /// Whether this organization uses SSH keys (if disabled, the section is not shown).
        enabled: bool,
        /// Whether identity confirmation by passkey is still valid.
        passkey_fresh: bool,
        keys: Vec<AccountSshKeySummary>,
    },
    SessionExpired,
    Internal,
}

/// Request of the SSH key registration API (`POST /internal/account/ssh-keys/register`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountRegisterSshKeyRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    /// The pasted public key (one authorized_keys line).
    pub public_key: String,
    pub name: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountRegisterSshKeyResponse {
    Registered {
        fingerprint: String,
    },
    Disabled,
    /// More than 5 minutes have passed since identity confirmation by passkey. web sends the user to passkey confirmation.
    PasskeyRequired,
    InvalidName,
    /// Something resembling a private key was pasted (not saved).
    PrivateKey,
    /// Not an sk type.
    NotSecurityKey,
    /// The format is broken.
    Malformed,
    AlreadyRegistered,
    TooMany,
    SessionExpired,
    Internal,
}

/// Request of the SSH key revocation API (`POST /internal/account/ssh-keys/revoke`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountRevokeSshKeyRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    pub key_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountRevokeSshKeyResponse {
    Revoked,
    PasskeyRequired,
    NotFound,
    SessionExpired,
    Internal,
}

/// Request of the security screen content API (`POST /internal/account/security`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountSecurityRequest {
    /// The flow's tenant (required because connected apps are held per tenant).
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Raw value of the SSO session cookie (forwarded by web).
    pub sso_session_id: String,
}

/// Response of the security screen content API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountSecurityResponse {
    Ok {
        sessions: Vec<AccountSessionSummary>,
        connected_apps: Vec<AccountConnectedAppSummary>,
    },
    /// No SSO session, expired, or the user is disabled.
    SessionExpired,
    Internal,
}

/// Request of the session revocation API (`POST /internal/account/security/revoke-session`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountRevokeSessionRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    /// The display ID shown in [`AccountSessionSummary::id`].
    pub session_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the session revocation API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountRevokeSessionResponse {
    /// Revoked (including when it was already gone).
    Ok,
    /// The given ID is not among the user's sessions (another person's session, or a resend from an old screen).
    NotFound,
    /// The session in use itself cannot be cut (sent to the logout flow).
    CurrentSession,
    SessionExpired,
    Internal,
}

/// Request of the disconnect API (`POST /internal/account/security/revoke-consent`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountRevokeConsentRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    pub client_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the disconnect API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountRevokeConsentResponse {
    /// Revoked (including when there was no consent).
    Ok,
    SessionExpired,
    Internal,
}

/// Request of the token reissue API (`POST /internal/account/security/reissue-tokens`; ADR-0047).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountReissueTokensRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the token reissue API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountReissueTokensResponse {
    /// Revoked. `revoked` is the number dropped, and **0 is also success** (there were no live tokens).
    Ok {
        revoked: u64,
    },
    SessionExpired,
    Internal,
}

// ── Step-up authentication (AP5) ──────────────────────────────────────────────────────

/// Sensitive operations handled by the step-up check and verification APIs. Values match the string representation
/// of `domain::step_up::SensitiveOperation` (api `parse`s them).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalStepUpCheckRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Raw value of the SSO session cookie (forwarded by web).
    pub sso_session_id: String,
    /// Target operation (`change_password` / `manage_authenticators` / `manage_external_identities` /
    /// `revoke_session`).
    pub operation: String,
}

/// Response of the step-up check API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalStepUpCheckResponse {
    /// The recent identity confirmation meets the requirement. The operation may proceed as is.
    Satisfied,
    /// Identity confirmation must be redone. If `second_factor_required` is true, TOTP is required too.
    ChallengeRequired {
        second_factor_required: bool,
        /// Whether passkey confirmation may be shown on screen (the user has a passkey **usable now**).
        /// Showing the button to a user without one would fail after the browser dialog appears.
        #[serde(default)]
        passkey_available: bool,
        /// Whether the operation can be confirmed only by passkey (device registration; task #872). The screen shows no
        /// password field, and says so if there is no passkey.
        #[serde(default)]
        passkey_only: bool,
    },
    /// No SSO session, expired, or the user is disabled.
    SessionExpired,
    /// Unknown operation name (a value api does not accept).
    UnknownOperation,
    Internal,
}

/// Request of the step-up verification API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalStepUpVerifyRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    pub operation: String,
    pub password: String,
    /// Needed only when a second factor is required.
    #[serde(default)]
    pub totp_code: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the step-up verification API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalStepUpVerifyResponse {
    /// Confirmed. The operation may continue.
    Ok,
    /// The password or TOTP does not match (which one is not returned).
    InvalidCredentials,
    /// A second factor is required but no code was presented.
    SecondFactorRequired,
    RateLimited,
    SessionExpired,
    UnknownOperation,
    Internal,
}

/// Request of the API starting identity confirmation by passkey (`POST /internal/step-up/passkey/begin`).
///
/// It is separate from the login start (`/internal/passkey/login/begin`) **to issue challenges of a different
/// purpose** (extending the idea of decision 4 of ADR-0040 to identity confirmation). A challenge issued here
/// cannot complete a login, and the reverse does not pass either.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalStepUpPasskeyBeginRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
}

/// Response of the API starting identity confirmation by passkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalStepUpPasskeyBeginResponse {
    Ok {
        challenge_id: String,
        /// Options (JSON) passed to `navigator.credentials.get()`.
        options: serde_json::Value,
    },
    SessionExpired,
    Internal,
}

/// Request of the identity confirmation by passkey API (`POST /internal/step-up/passkey/verify`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalStepUpPasskeyVerifyRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    pub operation: String,
    pub challenge_id: String,
    /// `PublicKeyCredential` (JSON) returned by the browser.
    pub credential: serde_json::Value,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the identity confirmation by passkey API.
///
/// Unlike the password path ([`InternalStepUpVerifyResponse`]), it never returns `SecondFactorRequired`:
/// a passkey satisfies multiple factors at once, so there is no further factor to add (ADR-0020 §3 / decision 2 of ADR-0040).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalStepUpPasskeyVerifyResponse {
    /// Confirmed. The operation may continue.
    Ok,
    /// The assertion is invalid, the challenge was not found, or it is not the user's passkey (reasons not distinguished).
    InvalidCredential,
    RateLimited,
    SessionExpired,
    UnknownOperation,
    Internal,
}

// ── Unified authenticator management (AP9) ──────────────────────────────────────────────────

/// Summary of one registered authenticator (security screen).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSummaryResponse {
    pub id: String,
    /// Kind (`totp` / `webauthn` / `email_otp`). Recovery codes are returned separately as a count.
    pub authenticator_type: String,
    /// State (`pending` / `active` / `suspended`). Revoked ones are not returned.
    pub status: String,
    pub label: String,
    pub created_at: String,
    #[serde(default)]
    pub last_used_at: Option<String>,
}

/// Request of the authenticator list API (`POST /internal/account/authenticators`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAuthenticatorsRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
}

/// Response of the authenticator list API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAuthenticatorsResponse {
    Ok {
        authenticators: Vec<AuthenticatorSummaryResponse>,
        /// Number of unused recovery codes remaining.
        recovery_codes_remaining: usize,
        /// Whether a confirmed phone number is registered (AP13). The number itself is not returned
        /// (PII is not carried out to web; the screen only varies between "registered" and "register").
        #[serde(default)]
        phone_registered: bool,
        /// Whether an SMS gateway is configured (AP13). If not, the registration path is not shown
        /// (do not show a screen that can register but cannot send).
        #[serde(default)]
        sms_available: bool,
    },
    SessionExpired,
    Internal,
}

/// Request of the authenticator state change API (`POST /internal/account/authenticators/status`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAuthenticatorStatusRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    pub authenticator_id: String,
    /// Target state (`active` / `suspended` / `revoked`).
    pub status: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the authenticator state change API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAuthenticatorStatusResponse {
    Ok,
    /// The given ID is not among the user's authenticators.
    NotFound,
    /// Cannot transition to that state (e.g. restoring a revoked one).
    InvalidTransition,
    /// Unknown state name.
    UnknownStatus,
    SessionExpired,
    Internal,
}

/// Request of the recovery code issuance API (`POST /internal/account/recovery-codes`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalRecoveryCodesRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the recovery code issuance API. **Plain text is returned only in this response** (the DB holds only hashes).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalRecoveryCodesResponse {
    Ok { codes: Vec<String> },
    SessionExpired,
    Internal,
}

/// Request of the email OTP sending API (`POST /internal/account/email-otp`).
///
/// Used as a second factor during login, so it must refer to **the user awaiting MFA**, not an `sso_session_id`.
/// web holds the login flow's `auth_session_id` (OIDC) or `mfa_ticket` (portal),
/// so api resolves the user from that.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalEmailOtpRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// `auth_session_id` of the OIDC login flow (awaiting MFA).
    #[serde(default)]
    pub auth_session_id: Option<String>,
    /// `mfa_ticket` of the portal login.
    #[serde(default)]
    pub mfa_ticket: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the email OTP sending API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalEmailOtpResponse {
    /// Sent (the destination address is not returned).
    Sent,
    /// SMTP is not configured, so no email can be sent.
    Unavailable,
    /// Resent too soon or too often (the previous code stays valid).
    RateLimited,
    /// Not in the awaiting-MFA state (the session or ticket is invalid).
    SessionExpired,
    Internal,
}

// ── SMS OTP and phone number registration (AP13) ─────────────────────────────────────────

/// Request to send an SMS OTP to a user awaiting MFA. Resolved the same way as email OTP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalSmsOtpRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// `auth_session_id` of the OIDC login flow (awaiting MFA).
    #[serde(default)]
    pub auth_session_id: Option<String>,
    /// `mfa_ticket` of the portal login.
    #[serde(default)]
    pub mfa_ticket: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the SMS OTP sending API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalSmsOtpResponse {
    /// Sent (the destination phone number is not returned: PII is not carried out to web).
    Sent,
    /// No SMS gateway is configured, so it cannot be sent.
    Unavailable,
    /// The destination phone number is unregistered or unconfirmed.
    NotRegistered,
    /// Resent too soon or too often (the previous code stays valid).
    RateLimited,
    /// Not in the awaiting-MFA state (the session or ticket is invalid).
    SessionExpired,
    Internal,
}

/// Start of phone number registration (sending a confirmation code). A self-service operation by a logged-in user,
/// so the target is resolved from `sso_session_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPhoneRegistrationRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    /// The phone number as entered (api normalizes it).
    pub phone_number: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of starting phone number registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPhoneRegistrationResponse {
    /// The confirmation code was sent.
    Sent,
    /// Cannot be read as a phone number.
    InvalidPhoneNumber,
    /// No SMS gateway is configured, so it cannot be sent.
    Unavailable,
    Unauthenticated,
    Internal,
}

/// Confirmation of phone number registration (presenting the sent code).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPhoneConfirmationRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    pub code: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of confirming phone number registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPhoneConfirmationResponse {
    /// Confirmed (SMS OTP can be used from now on).
    Confirmed,
    /// The code does not match, has expired, or there is no registration awaiting confirmation.
    InvalidCode,
    Unauthenticated,
    Internal,
}

// ── External IdP login (AP10) ────────────────────────────────────────────────

/// One external IdP listed on the login screen (enabled ones only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalIdpButton {
    /// Identifier code put in the URL.
    pub provider_code: String,
    pub display_name: String,
}

/// Request of the enabled external IdP list API (`POST /internal/external/providers`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalExternalProvidersRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// Response of the enabled external IdP list API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalExternalProvidersResponse {
    Ok { providers: Vec<ExternalIdpButton> },
    Internal,
}

/// Request of the external IdP login start API (`POST /internal/external/start`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalExternalStartRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub provider_code: String,
    /// `auth_session_id` when called mid OIDC authorization flow (`None` via the portal).
    #[serde(default)]
    pub auth_session_id: Option<String>,
}

/// Response of the external IdP login start API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalExternalStartResponse {
    /// 302 to the external IdP's authorization endpoint.
    Redirect {
        location: String,
        /// Value handed only to the browser that started it (task #581). web puts it in a cookie and returns it
        /// to api as `browser_binding` at the return endpoint. Old api does not return it (`None`).
        #[serde(default)]
        browser_binding: Option<String>,
    },
    /// The provider is missing or disabled.
    ProviderUnavailable,
    Internal,
}

/// Request of the callback API from an external IdP (`POST /internal/external/callback`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalExternalCallbackRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub state: String,
    pub code: String,
    /// The value put in the cookie at start (task #581). If missing or different, the progress state cannot be used.
    #[serde(default)]
    pub browser_binding: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Request of the API receiving an external SAML IdP's assertion (AP12; ADR-0027).
///
/// Passes the values the browser carried to web's ACS via the HTTP-POST binding to api as is.
/// **Both are unverified** (api checks the signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalExternalSamlAcsRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// `SAMLResponse` (base64(XML)).
    pub saml_response: String,
    /// `RelayState` (the value issued at start; the key to look up the progress state).
    pub relay_state: String,
    /// The value put in the cookie at start (task #581). If missing or different, the progress state cannot be used.
    #[serde(default)]
    pub browser_binding: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Response of the callback API from an external IdP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalExternalCallbackResponse {
    /// Authenticated. Turn `sso_session_id` into a cookie and send to `redirect_to`.
    ///
    /// `redirect_to` is the `redirect_uri` with code (absolute URL back to the RP) if it came mid OIDC authorization
    /// flow, otherwise `None` (web returns to its own account screen).
    /// The authorization request parameters exist only in api's auth_session, so web is not made to build it.
    Success {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
        #[serde(default)]
        redirect_to: Option<String>,
        /// Hidden fields POSTed for `form_post` (G12). `None` means `query`.
        #[serde(default)]
        form_post: Option<FormPostFields>,
        #[serde(default)]
        user_language: Option<String>,
    },
    /// Authenticated, but consent to the RP is still pending. web leads to the consent screen.
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
        #[serde(default)]
        user_language: Option<String>,
    },
    /// `state` is invalid, expired, or used twice.
    StateExpired,
    /// Authenticated at the external IdP, but there is no corresponding user.
    NotLinked,
    /// The corresponding user exists but is disabled or locked.
    UserUnavailable,
    /// Refused by an authentication policy.
    PolicyDenied,
    /// Authenticated, but use of this app is not permitted (ADR-0054). ⚠ **Not returned to the RP.**
    /// web refuses on assay's screen: to the user it is "I got in and was then kicked out", so it shows the fact that
    /// authentication passed, the app name, and a way to ask the admin.
    ApplicationNotPermitted {
        application_name: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
        #[serde(default)]
        user_language: Option<String>,
    },
    /// Communication with the external IdP or token verification failed.
    ExternalFailure,
    Internal,
    /// Authenticated, but on an unregistered device in an organization limited to registered devices (task #916, ADR-0079).
    /// No SSO cookie. web puts `ticket` in a cookie and sends the user to the device registration screen.
    DeviceEnrollmentRequired {
        ticket: String,
    },
}

/// Request of the sign-in history API (`POST /internal/account/sign-in-history`; task #879).
///
/// The user is determined by the SSO session's owner (no user id is accepted = no one else's history can be fetched).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountSignInHistoryRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    /// Only rows older than this (`next_before` of the previous page).
    #[serde(default)]
    pub before: Option<i64>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountSignInHistoryResponse {
    Ok {
        entries: Vec<AccountSignInEntry>,
        #[serde(default)]
        next_before: Option<i64>,
    },
    SessionExpired,
    Internal,
}

/// One sign-in history row. Client address and browser are those of the browser that signed in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSignInEntry {
    pub id: i64,
    /// RFC 3339 (UTC).
    pub occurred_at: String,
    /// `succeeded` / `failed` / `locked` / `denied`.
    pub outcome: String,
    /// Kind of refusal reason (`wrong_password` etc.; `None` on success).
    #[serde(default)]
    pub failure_kind: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    /// Country code (`None` when unknown or untrusted).
    #[serde(default)]
    pub country: Option<String>,
    /// Methods verified (`password` / `totp` / `webauthn` / `recovery_code` / `external_idp` etc.).
    #[serde(default)]
    pub methods: Vec<String>,
    /// The app that started the refused login (if known).
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    /// Whether it was a registered device (task #872; `None` without a device mark).
    #[serde(default)]
    pub device_registered: Option<bool>,
    /// Whether this is the very login state being viewed now.
    #[serde(default)]
    pub current: bool,
    /// Apps entered with this login (successful logins only).
    #[serde(default)]
    pub apps: Vec<AccountSignInApp>,
}

/// An app entered with the login and how that app's refresh token was used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSignInApp {
    pub client_id: String,
    #[serde(default)]
    pub app_name: Option<String>,
    pub first_issued_at: String,
    pub last_issued_at: String,
    /// `None` if no refresh token was issued.
    #[serde(default)]
    pub refresh: Option<AccountRefreshUsage>,
}

/// How a refresh token was used. Client address and identity are those of **whoever sent the refresh** (the app's server etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRefreshUsage {
    pub use_count: u32,
    #[serde(default)]
    pub last_used_at: Option<String>,
    #[serde(default)]
    pub last_ip_address: Option<String>,
    #[serde(default)]
    pub last_user_agent: Option<String>,
    #[serde(default)]
    pub reuse_detected_at: Option<String>,
    /// `active` / `revoked` / `expired`.
    pub state: String,
    #[serde(default)]
    pub revoked_at: Option<String>,
}

/// Header with which web adds the "country it decided to trust" (`CF-IPCountry`) to internal calls to api (task #895).
///
/// api reads this header only on `/internal/*` (behind the service token). The same header on requests coming to api
/// directly from outside is not read (anyone can set it).
pub const CLIENT_COUNTRY_HEADER: &str = "x-assay-client-country";

/// Header with which web adds the current browser's device mark (plain value of the `assay_device` cookie) to internal
/// calls to api (task #916, ADR-0079). Used by api to decide whether a login may complete in organizations limited to registered devices.
///
/// api reads this header only on `/internal/*` (behind the service token).
pub const CLIENT_DEVICE_HEADER: &str = "x-assay-client-device";

/// Binds the SSO session to the device key (DBSC registration; `POST /internal/sso/key-binding/register`; task #887, ADR-0074).
///
/// web passes the signature (JWT) received from Chrome and the SSO session cookie attached to that request as is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalSessionKeyRegisterRequest {
    pub sso_session_id: String,
    /// Value of `Secure-Session-Response` (JWT).
    pub proof: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Refreshing the binding (`POST /internal/sso/key-binding/refresh`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalSessionKeyRefreshRequest {
    pub sso_session_id: String,
    /// Value of `Sec-Secure-Session-Id`.
    pub session_identifier: String,
    /// Value of `Secure-Session-Response` (JWT).
    pub proof: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Result of registration or refresh.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalSessionKeyResponse {
    /// Bound (refreshed). web issues the short cookie and resets the long cookie's `Max-Age` to
    /// `remaining_secs`.
    Bound {
        session_identifier: String,
        remaining_secs: u64,
    },
    /// The signature, challenge or shape does not match (the binding is not changed).
    Rejected,
    /// Signed with a key different from the registered one. The login state was ended.
    KeyMismatch,
    /// No login state, it has expired, or the binding identifier differs.
    SessionGone,
    Internal,
}

/// Whether the SSO session is bound to a device key (`POST /internal/sso/key-binding`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalSessionKeyBindingRequest {
    pub sso_session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalSessionKeyBindingResponse {
    /// Bound (`session_identifier` is handed to Chrome in the refresh 403).
    Bound {
        session_identifier: String,
    },
    /// Not bound (a nonexistent session also lands here).
    Unbound,
    Internal,
}

// ─── Logins approved with the authenticator app (task #892, ADR-0077) ───────────────────

/// Starts a "continue with the app" request (`POST /internal/app-approval/start`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAppApprovalStartRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// If it came mid-authorization, that browser's `auth_session_id` (plain cookie value).
    #[serde(default)]
    pub auth_session_id: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAppApprovalStartResponse {
    Started {
        request_id: String,
        /// Mark handed only to the starting browser. web puts it in a cookie (the DB holds only SHA-256).
        browser_binding: String,
    },
    /// The authenticator app routes are closed.
    Disabled,
    RateLimited,
    Internal,
}

/// Completes in the browser the app opened (`POST /internal/app-approval/complete`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAppApprovalCompleteRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub request_id: String,
    pub code: String,
    /// The request mark (cookie) that browser had. `None` if absent.
    #[serde(default)]
    pub browser_binding: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAppApprovalCompleteResponse {
    /// Logged in. If there is no `redirect_to`, go to assay's account screen.
    Success {
        #[serde(default)]
        redirect_to: Option<String>,
        #[serde(default)]
        form_post: Option<FormPostFields>,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    ApplicationNotPermitted {
        application_name: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// The code is wrong, expired or used.
    Invalid,
    /// A browser other than the one that started the request. No login was done.
    AnotherBrowser,
    PolicyDenied,
    UserUnavailable,
    Internal,
}

/// Authenticator app registration confirmation screen (`POST /internal/account/app-approver/enrollment`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountApproverEnrollmentRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    pub enrollment_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountApproverEnrollmentResponse {
    Ready {
        device_name: String,
        /// `tee` / `strongbox` / `software`
        security_level: String,
        created_at: String,
    },
    NotFound,
    SessionExpired,
    Internal,
}

/// Confirms the authenticator app registration (`POST /internal/account/app-approver/confirm`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountApproverConfirmResponse {
    /// Code returned to the app (put on the Auth Tab return target).
    Confirmed {
        code: String,
    },
    /// More than 5 minutes have passed since confirming with a passkey (sent to the identity confirmation screen).
    PasskeyRequired,
    NotFound,
    SessionExpired,
    Internal,
}

/// One "authenticator app" row of the "devices" section. Times are RFC 3339.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountApproverKeySummary {
    pub id: String,
    pub device_name: String,
    pub security_level: String,
    pub registered_at: String,
    #[serde(default)]
    pub last_used_at: Option<String>,
}

/// The "authenticator app" list (`POST /internal/account/app-approver/keys`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountApproverKeysRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountApproverKeysResponse {
    Listed {
        /// `false` if the authenticator app routes are closed (the screen hides the whole section).
        enabled: bool,
        keys: Vec<AccountApproverKeySummary>,
    },
    SessionExpired,
    Internal,
}

/// Revokes an authenticator app key (`POST /internal/account/app-approver/keys/revoke`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountRevokeApproverKeyRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    pub key_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountRevokeApproverKeyResponse {
    Revoked { sessions: usize },
    NotFound,
    SessionExpired,
    Internal,
}

/// Request of the "status" API (`POST /internal/account/security/status`; task #896, ADR-0078).
///
/// The user is determined by the SSO session's owner (no user id is accepted = no one else's status can be fetched).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountSecurityStatusRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountSecurityStatusResponse {
    Ok {
        /// The current login state first, then newest first.
        sessions: Vec<AccountSessionStatus>,
        belongings: Vec<AccountBelonging>,
        apps: Vec<AccountAppTokens>,
        policy: AccountSecurityPolicy,
        /// Boxed to keep the enum size down (the JSON shape does not change).
        warnings: Box<AccountSecurityWarnings>,
    },
    SessionExpired,
    Internal,
}

/// Status of one login state. All times are RFC 3339 (UTC).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSessionStatus {
    /// The same value as the existing "login state" row (`AccountSessionSummary::id`).
    pub id: String,
    pub current: bool,
    pub auth_time: String,
    pub created_at: String,
    /// Expiry time (the earlier of idle and absolute).
    pub expires_at: String,
    /// Methods verified (`password` / `webauthn` / `totp` / `app_approval` …; in verification order).
    #[serde(default)]
    pub methods: Vec<String>,
    pub multi_factor: bool,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    /// Whether the device mark of the browser that created the login state is known.
    pub device_identified: bool,
    /// If a registered device, its name, registration time and last used time.
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(default)]
    pub device_registered_at: Option<String>,
    #[serde(default)]
    pub device_last_used_at: Option<String>,
    /// `unbound` / `device_key` / `app_approval`.
    pub binding: String,
    /// Basis of the lifetime (`bound_on_registered_device` / `app_approval` / `bound_on_unregistered_device` /
    /// `unbound` / `not_extended_by_setting`).
    pub lifetime_basis: String,
    /// Device key (DBSC).
    #[serde(default)]
    pub key_algorithm: Option<String>,
    #[serde(default)]
    pub key_thumbprint: Option<String>,
    #[serde(default)]
    pub key_bound_at: Option<String>,
    #[serde(default)]
    pub key_refreshed_at: Option<String>,
    /// Model name of the approving authenticator app and where its key is stored (`tee` / `strongbox` / `software`).
    #[serde(default)]
    pub approver_device_name: Option<String>,
    #[serde(default)]
    pub approver_security_level: Option<String>,
    /// Expiry while the passkey identity confirmation is still fresh (`None` if past).
    #[serde(default)]
    pub passkey_fresh_until: Option<String>,
}

/// One trusted possession.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountBelonging {
    /// `passkey` / `totp` / `approver_key` / `device` / `ssh_key`.
    pub kind: String,
    pub name: String,
    /// Per-kind detail (authenticator app key storage, device name, SSH key type).
    #[serde(default)]
    pub detail: Option<String>,
    pub registered_at: String,
    /// Always `None` for things whose use is not visible from assay (SSH keys).
    #[serde(default)]
    pub last_used_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// Token kind of one app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountAppTokens {
    pub client_id: String,
    pub app_name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub active_refresh_tokens: u32,
    pub dpop_bound_refresh_tokens: u32,
    #[serde(default)]
    pub last_issued_at: Option<String>,
    pub refresh_use_count: u32,
    #[serde(default)]
    pub refresh_last_used_at: Option<String>,
    #[serde(default)]
    pub refresh_last_ip: Option<String>,
    #[serde(default)]
    pub refresh_last_user_agent: Option<String>,
    #[serde(default)]
    pub refresh_reuse_detected_at: Option<String>,
}

/// Organization rules in effect for oneself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSecurityPolicy {
    pub unregistered_device_alerts: bool,
    pub ssh_keys_enabled: bool,
    pub idle_ttl_secs: i64,
    pub absolute_ttl_secs: i64,
    pub bound_ttl_secs: i64,
    pub device_expiry_days: i64,
}

/// Warnings in the last 30 days.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountSecurityWarnings {
    pub window_days: i64,
    pub refresh_reuse: AccountOccurrences,
    pub session_key_mismatch: AccountOccurrences,
    pub dpop_key_mismatch: AccountOccurrences,
    pub unregistered_sign_ins: AccountOccurrences,
    /// Days (`YYYY-MM-DD`, UTC) with many refused logins, and their counts.
    #[serde(default)]
    pub failure_days: Vec<AccountFailureDay>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountOccurrences {
    pub count: u32,
    #[serde(default)]
    pub last_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountFailureDay {
    pub day: String,
    pub count: u32,
}

/// Looks at the content of the device registration ticket (task #916) (`POST /internal/device-enrollment/describe`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalDeviceEnrollmentDescribeRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Value of the `__Host-device_enrollment` cookie.
    pub ticket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalDeviceEnrollmentDescribeResponse {
    Ok {
        /// Whose login it is (shown on screen).
        username: String,
    },
    /// No ticket, expired, or another browser. **Not distinguished** (start over from login).
    TicketInvalid,
    Internal,
}

/// Starts passkey verification for device registration (`POST /internal/device-enrollment/passkey/begin`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalDeviceEnrollmentBeginRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub ticket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalDeviceEnrollmentBeginResponse {
    Ok {
        challenge_id: String,
        /// JSON passed to the browser's `navigator.credentials.get()`.
        options: serde_json::Value,
    },
    TicketInvalid,
    Internal,
}

/// Verifies with a passkey, registers this browser as a device and logs in
/// (`POST /internal/device-enrollment/passkey/complete`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalDeviceEnrollmentCompleteRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub ticket: String,
    pub challenge_id: String,
    pub credential: serde_json::Value,
    /// Name given to the device (typed on screen).
    pub device_name: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalDeviceEnrollmentCompleteResponse {
    /// Registered and logged in. web turns `sso_session_id` into a cookie, deletes the ticket cookie and returns to the original screen.
    Enrolled {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    TicketInvalid,
    /// The passkey did not pass, or it is not the passkey of the ticket's person.
    PasskeyRejected,
    /// The device name is empty or too long.
    InvalidName,
    /// The account cannot be used (disabled, locked etc.).
    AccountUnavailable,
    Internal,
}
