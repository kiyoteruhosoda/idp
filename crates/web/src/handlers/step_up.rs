//! Step-up authentication re-verification screen (web. `/{tenant_id}/settings/verify`. AP5).
//!
//! [`require_step_up`] is called at the entry of sensitive operations (adding/removing authenticators, revoking sessions, etc.),
//! and if insufficient, the user is led to this screen. Once verified, it returns to the original screen (`next`).
//!
//! Decisions and verification are done by the api (`/internal/step-up/*`); web handles only the screen and the safety of `next`.
//!
//! There are two means of verification: **password** (plus TOTP if multi-factor is required) and **passkey** (T38).
//! The latter is the path for users who signed in with a passkey — authenticator management is subject to step-up,
//! so accepting only passwords would mean "signed in with a passkey but cannot add a passkey".
//! The passkey path goes through the browser's WebAuthn API, so it is a two-step JSON exchange (begin / complete),
//! sharing `assets/passkey-login.js` with the login screen (only the completion target differs).
//!
//! # Handling `next`
//!
//! `next` can carry any value from the browser. Only **this tenant's paths** within the same origin are accepted
//! (to avoid an open redirect). A "scheme-less absolute URL" like `//evil.example.com` is resolved
//! by the browser as another origin, so merely checking for a leading `/` is not enough.

use super::{api_internal_error, internal_call_status};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_token, console_csrf_valid};
use crate::handlers::{forwarded_context, found, locale, see_other};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, StepUpChallenge};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalStepUpCheckRequest, InternalStepUpCheckResponse, InternalStepUpPasskeyBeginRequest,
    InternalStepUpPasskeyBeginResponse, InternalStepUpPasskeyVerifyRequest,
    InternalStepUpPasskeyVerifyResponse, InternalStepUpVerifyRequest, InternalStepUpVerifyResponse,
};
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;
use serde_json::json;

/// Identifiers of sensitive operations (keep equal to the string form of the api's `domain::step_up::SensitiveOperation`).
/// web-side callers use these constants instead of scattering literals (a misspelling makes the api return
/// `UnknownOperation` and the screen a 500).
pub const MANAGE_AUTHENTICATORS: &str = "manage_authenticators";
pub const REVOKE_SESSION: &str = "revoke_session";
/// Device registration (task #872). Passable only by passkey.
pub const REGISTER_DEVICE: &str = "register_device";
/// Registering/revoking SSH public keys (task #885). Passable only by passkey.
pub const MANAGE_SSH_KEYS: &str = "manage_ssh_keys";

#[derive(Debug, Deserialize)]
pub struct StepUpQuery {
    /// Where to return after verification (only paths under this tenant).
    #[serde(default)]
    pub next: Option<String>,
    /// Target operation (same string as the api's `SensitiveOperation`).
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StepUpForm {
    pub operation: String,
    pub next: String,
    pub password: String,
    #[serde(default)]
    pub totp_code: Option<String>,
    pub csrf_token: String,
}

/// The gate's decision (the response shape depends on the caller's path, so only the decision is returned here).
enum Gate {
    /// The operation may proceed.
    Pass,
    /// Re-verification needed. The value is the screen to lead to.
    Challenge(String),
    /// Start over from login.
    LoginRequired,
    /// A failure not due to this path (api unreachable, implementation inconsistency).
    Failed(StatusCode),
}

/// Confines the gate decision to one place (both HTML and JSON paths go through here).
async fn evaluate(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    headers: &HeaderMap,
    operation: &str,
    next: &str,
) -> Gate {
    let Some(sso) = cookies::get(headers, cookies::SSO_SESSION_COOKIE) else {
        return Gate::LoginRequired;
    };
    let request = InternalStepUpCheckRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        operation: operation.to_string(),
    };
    match state.api.step_up_check(&correlation.0, &request).await {
        Ok(InternalStepUpCheckResponse::Satisfied) => Gate::Pass,
        Ok(InternalStepUpCheckResponse::ChallengeRequired { .. }) => {
            Gate::Challenge(challenge_path(tenant, operation, next))
        }
        Ok(InternalStepUpCheckResponse::SessionExpired) => Gate::LoginRequired,
        Ok(InternalStepUpCheckResponse::UnknownOperation) => {
            // The caller passes a constant, so reaching here means an implementation inconsistency. Stop fail-closed.
            tracing::error!(operation, "step-up check rejected an unknown operation");
            Gate::Failed(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Ok(InternalStepUpCheckResponse::Internal) => {
            // This is **the gate's entry**; failing makes the whole screen a 500. Unless we record which call
            // it stopped at, all users see is a bare 500.
            tracing::error!(call = "step_up_check", "api reported an internal error");
            Gate::Failed(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(e) => {
            tracing::error!(error = %e, "step-up check call to api failed");
            Gate::Failed(internal_call_status(&e))
        }
    }
}

/// Gate called at the entry of sensitive operations (for HTML paths with screen transitions).
///
/// `Ok(())` means the operation may proceed. `Err(response)` is returned by the caller as is (a redirect to the
/// re-verification screen, or leading to the login screen when not signed in).
pub async fn require_step_up(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    headers: &HeaderMap,
    operation: &str,
    next: &str,
) -> Result<(), Response> {
    match evaluate(state, correlation, tenant, headers, operation, next).await {
        Gate::Pass => Ok(()),
        Gate::Challenge(path) => Err(found(&path)),
        Gate::LoginRequired => Err(found(&format!("{}/login", tenant.prefix()))),
        Gate::Failed(status) => Err(status.into_response()),
    }
}

/// The same gate for JSON APIs (mutating endpoints called from `fetch`).
///
/// **Protecting only the screen handlers is pointless.** The screen is just the entry guide; what actually creates
/// authenticators is the JSON endpoint, which a caller holding a stolen cookie can hit directly without the screen.
/// Returning a redirect would make `fetch` silently follow it and read HTML as JSON, so this one returns
/// 403 carrying the destination and lets the script do the navigation.
pub async fn require_step_up_api(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    headers: &HeaderMap,
    operation: &str,
    next: &str,
) -> Result<(), Response> {
    match evaluate(state, correlation, tenant, headers, operation, next).await {
        Gate::Pass => Ok(()),
        Gate::Challenge(path) => Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "result": "step_up_required", "location": path })),
        )
            .into_response()),
        Gate::LoginRequired => Err(StatusCode::UNAUTHORIZED.into_response()),
        Gate::Failed(status) => Err(status.into_response()),
    }
}

/// Re-verification screen (`GET /{tenant_id}/settings/verify`).
pub async fn page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<StepUpQuery>,
) -> Response {
    let locale = locale(&headers);
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    let operation = query.operation.unwrap_or_default();
    let next = safe_next(&tenant, query.next.as_deref());
    let csrf = console_csrf_token(&sso, state.config.csrf_secret());

    // Whether to require the second factor follows the api's decision (if the screen guessed on its own it would diverge from the requirement).
    let request = InternalStepUpCheckRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        operation: operation.clone(),
    };
    let (second_factor_required, passkey_available, passkey_only) =
        match state.api.step_up_check(&correlation.0, &request).await {
            Ok(InternalStepUpCheckResponse::ChallengeRequired {
                second_factor_required,
                passkey_available,
                passkey_only,
            }) => (second_factor_required, passkey_available, passkey_only),
            // If already satisfied (verified in another tab etc.), return as is.
            Ok(InternalStepUpCheckResponse::Satisfied) => return found(&next),
            Ok(InternalStepUpCheckResponse::SessionExpired) => {
                return found(&format!("{}/login", tenant.prefix()));
            }
            Ok(InternalStepUpCheckResponse::UnknownOperation) => {
                return StatusCode::BAD_REQUEST.into_response();
            }
            Ok(InternalStepUpCheckResponse::Internal) => {
                return api_internal_error("step_up_check");
            }
            Err(e) => {
                tracing::error!(error = %e, "step-up check call to api failed");
                return internal_call_status(&e).into_response();
            }
        };

    let messages = Messages::new(locale);
    Html(render(&StepUpChallenge {
        messages: &messages,
        tenant: &tenant.prefix(),
        csrf: &csrf,
        operation: &operation,
        next: &next,
        second_factor_required,
        passkey_available,
        passkey_only,
        error_key: query.error.as_deref().and_then(error_key_for),
    }))
    .into_response()
}

/// Performs re-verification (`POST /{tenant_id}/settings/verify`).
pub async fn verify(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<StepUpForm>,
) -> Response {
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    let next = safe_next(&tenant, Some(&form.next));
    let challenge = challenge_path(&tenant, &form.operation, &next);

    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        tracing::warn!(
            correlation_id = %correlation.0,
            "step-up verification rejected: csrf token mismatch"
        );
        return see_other(&format!("{challenge}&error=csrf"));
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalStepUpVerifyRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        operation: form.operation.clone(),
        password: form.password,
        totp_code: form.totp_code,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .step_up_verify(&ctx.correlation_id, &request)
        .await
    {
        Ok(InternalStepUpVerifyResponse::Ok) => see_other(&next),
        Ok(InternalStepUpVerifyResponse::InvalidCredentials) => {
            see_other(&format!("{challenge}&error=invalid"))
        }
        Ok(InternalStepUpVerifyResponse::SecondFactorRequired) => {
            see_other(&format!("{challenge}&error=second-factor"))
        }
        Ok(InternalStepUpVerifyResponse::RateLimited) => {
            see_other(&format!("{challenge}&error=rate-limited"))
        }
        Ok(InternalStepUpVerifyResponse::SessionExpired) => {
            found(&format!("{}/login", tenant.prefix()))
        }
        Ok(InternalStepUpVerifyResponse::UnknownOperation) => {
            StatusCode::BAD_REQUEST.into_response()
        }
        Ok(InternalStepUpVerifyResponse::Internal) => api_internal_error("step_up_verify"),
        Err(e) => {
            tracing::error!(error = %e, "step-up verify call to api failed");
            internal_call_status(&e).into_response()
        }
    }
}

// ─── Re-verification with a passkey (T38) ─────────────────────────────────────────────
//
// It goes through the browser's WebAuthn API, so it is a two-step JSON exchange rather than a form submission. The screen
// uses the same `assets/passkey-login.js` as the login screen, swapping only the begin/complete paths.
//
// No CSRF token is taken for the same reason as the login/registration passkey JSON APIs. A cross-origin POST
// to an endpoint accepting JSON requires a preflight (no CORS permission is granted)
// and does not get through at all. Moreover, completion needs **a signature made on the spot by that user's authenticator**.

/// Starts passkey re-verification (`POST /{tenant_id}/settings/verify/passkey/begin`).
pub async fn passkey_begin(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let request = InternalStepUpPasskeyBeginRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
    };
    match state
        .api
        .step_up_passkey_begin(&correlation.0, &request)
        .await
    {
        Ok(response @ InternalStepUpPasskeyBeginResponse::Ok { .. }) => {
            Json(response).into_response()
        }
        Ok(InternalStepUpPasskeyBeginResponse::SessionExpired) => {
            StatusCode::UNAUTHORIZED.into_response()
        }
        Ok(InternalStepUpPasskeyBeginResponse::Internal) => {
            api_internal_error("step_up_passkey_begin")
        }
        Err(e) => {
            tracing::error!(error = %e, "step-up passkey begin call to api failed");
            internal_call_status(&e).into_response()
        }
    }
}

/// Body received by the completion API. `operation` and `next` come back exactly as the screen passed them to the script
/// via `#passkey-error`'s data attributes (`next` is again restricted here to this tenant's paths —
/// values from the browser are not trusted).
#[derive(Debug, Deserialize)]
pub struct PasskeyCompleteBody {
    pub challenge_id: String,
    pub credential: serde_json::Value,
    #[serde(default)]
    pub operation: String,
    #[serde(default)]
    pub next: Option<String>,
}

/// Completes passkey re-verification (`POST /{tenant_id}/settings/verify/passkey/complete`).
///
/// On success returns `{ redirect_to }`, and the script navigates there (equivalent to the form path's 303).
pub async fn passkey_complete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Json(body): Json<PasskeyCompleteBody>,
) -> Response {
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let next = safe_next(&tenant, body.next.as_deref());
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalStepUpPasskeyVerifyRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        operation: body.operation,
        challenge_id: body.challenge_id,
        credential: body.credential,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .step_up_passkey_verify(&ctx.correlation_id, &request)
        .await
    {
        Ok(InternalStepUpPasskeyVerifyResponse::Ok) => Json(json!({ "redirect_to": next })),
        Ok(InternalStepUpPasskeyVerifyResponse::InvalidCredential) => {
            Json(json!({ "error": "invalid_credential" }))
        }
        Ok(InternalStepUpPasskeyVerifyResponse::RateLimited) => {
            Json(json!({ "error": "rate_limited" }))
        }
        // Showing wording would leave nothing to do, so make the user start over from login (same as the registration screen's 401).
        Ok(InternalStepUpPasskeyVerifyResponse::SessionExpired) => {
            Json(json!({ "redirect_to": format!("{}/login", tenant.prefix()) }))
        }
        Ok(InternalStepUpPasskeyVerifyResponse::UnknownOperation) => {
            // A value passed by the screen, so reaching here means an implementation inconsistency. Stop fail-closed.
            tracing::error!("step-up passkey verify rejected an unknown operation");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Ok(InternalStepUpPasskeyVerifyResponse::Internal) => {
            return api_internal_error("step_up_passkey_verify")
        }
        Err(e) => {
            tracing::error!(error = %e, "step-up passkey verify call to api failed");
            return internal_call_status(&e).into_response();
        }
    }
    .into_response()
}

/// Builds the URL to the re-verification screen.
fn challenge_path(tenant: &WebTenant, operation: &str, next: &str) -> String {
    fn encode(value: &str) -> String {
        percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
    }
    format!(
        "{}/settings/verify?operation={}&next={}",
        tenant.prefix(),
        encode(operation),
        encode(next)
    )
}

/// Restricts `next` to paths under this tenant (open redirect prevention).
///
/// Only paths starting with `/{tenant_id}` whose second character is not `/` are accepted. `//host` is
/// resolved by the browser as a scheme-relative URL to another origin, so a leading `/` alone is
/// insufficient. Values not meeting the conditions fall back to the settings screen.
pub(crate) fn safe_next(tenant: &WebTenant, next: Option<&str>) -> String {
    let fallback = format!("{}/settings", tenant.prefix());
    let Some(candidate) = next.filter(|v| !v.is_empty()) else {
        return fallback;
    };
    let prefix = tenant.prefix();
    // Check prefix matching with `strip_prefix`. **Never slice by byte position** — it panics on a `next`
    // shorter than the prefix (`/settings` etc.; the tenant prefix is a UUID of 37 chars) or on values
    // where the position is not a char boundary.
    let Some(rest) = candidate.strip_prefix(prefix.as_str()) else {
        return fallback;
    };
    // `\` is interpreted as `/` by some browsers, so it is rejected for the same reason as `//`.
    if candidate.starts_with("//") || candidate.contains('\\') {
        return fallback;
    }
    // To avoid "another tenant's prefix happening to match", also check that right after the prefix is a separator or the end
    // (do not let `/t123/...` pass for `/t1`).
    if rest.is_empty() || rest.starts_with('/') || rest.starts_with('?') {
        candidate.to_string()
    } else {
        fallback
    }
}

fn error_key_for(value: &str) -> Option<&'static str> {
    match value {
        "csrf" => Some("step-up-error-csrf"),
        "invalid" => Some("step-up-error-invalid"),
        "second-factor" => Some("step-up-error-second-factor"),
        "rate-limited" => Some("login-error-rate-limited"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> WebTenant {
        WebTenant("t1".to_string())
    }

    /// Only paths under the same tenant are accepted (no open redirect).
    #[test]
    fn next_is_restricted_to_this_tenants_paths() {
        let t = tenant();
        assert_eq!(
            safe_next(&t, Some("/t1/account/passkey")),
            "/t1/account/passkey"
        );
        assert_eq!(safe_next(&t, Some("/t1")), "/t1");
        assert_eq!(safe_next(&t, Some("/t1?x=1")), "/t1?x=1");

        let fallback = "/t1/settings";
        // External origin, scheme-relative, backslash, other tenant, empty.
        assert_eq!(safe_next(&t, Some("https://evil.example.com")), fallback);
        assert_eq!(safe_next(&t, Some("//evil.example.com")), fallback);
        assert_eq!(safe_next(&t, Some("/t1\\@evil.example.com")), fallback);
        assert_eq!(safe_next(&t, Some("/t2/admin")), fallback);
        assert_eq!(safe_next(&t, Some("/t123/admin")), fallback);
        assert_eq!(safe_next(&t, Some("")), fallback);
        assert_eq!(safe_next(&t, None), fallback);
    }

    /// **Does not crash on a `next` shorter than the prefix.** The tenant prefix is a UUID of 37 chars, so
    /// short values like `?next=/x` come in all the time (slicing by byte position would go out of range).
    #[test]
    fn a_next_shorter_than_the_tenant_prefix_falls_back_instead_of_panicking() {
        let t = WebTenant("00000000-0000-7000-8000-000000000001".to_string());
        let fallback = "/00000000-0000-7000-8000-000000000001/settings";
        assert_eq!(safe_next(&t, Some("/x")), fallback);
        assert_eq!(safe_next(&t, Some("https://evil.example.com/")), fallback);
        // Do not slice at a non-char-boundary position (values containing multibyte characters).
        assert_eq!(safe_next(&t, Some("/日本語のパス")), fallback);
    }

    /// The screen URL embeds operation and next percent-encoded.
    #[test]
    fn challenge_path_encodes_its_parameters() {
        let path = challenge_path(&tenant(), "manage_authenticators", "/t1/account/passkey");
        assert!(path.starts_with("/t1/settings/verify?"));
        assert!(path.contains("operation=manage%5Fauthenticators"));
        assert!(path.contains("next=%2Ft1%2Faccount%2Fpasskey"));
    }

    #[test]
    fn only_known_error_values_map_to_message_keys() {
        assert_eq!(error_key_for("invalid"), Some("step-up-error-invalid"));
        assert_eq!(error_key_for("<script>"), None);
    }
}
