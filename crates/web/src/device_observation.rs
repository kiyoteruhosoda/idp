//! Middleware telling the api which device signed in (task #872. ADR-0071).
//!
//! There are 5 login paths (OIDC, MFA, passkey, portal, admin console) plus external IdP and password change,
//! and all end by setting the SSO session cookie. Adding a call per path would miss some, so it looks
//! only at **whether the response newly set the SSO session cookie**, and in one place does the following:
//!
//! 1. if there is no device mark ([`DEVICE_COOKIE`]), create and set it (400 days; not reset on every use)
//! 2. tell the api's `/internal/devices/observe` that "this session was created on this device"
//!
//! ⚠ **Failing to tell it does not stop the login** (the response is already built). Failures are logged as errors.
//!
//! The country (`CF-IPCountry`) is read only when `TRUST_FORWARDED_HEADERS` is enabled (same as `X-Forwarded-For`).
//! For traffic from inside the home, homeedge passes this field empty (deploy-repo).

use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::state::WebState;
use assay_contracts::auth::{InternalDeviceObserveRequest, InternalDeviceObserveResponse};
use axum::extract::{Request, State};
use axum::http::header::{SET_COOKIE, USER_AGENT};
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

/// Cookie name of the device mark. The value is 64 hex characters (an unguessable random value).
pub const DEVICE_COOKIE: &str = "assay_device";
/// Lifetime of the device mark (400 days, the maximum Chrome accepts).
pub const DEVICE_COOKIE_MAX_AGE_SECS: u64 = 400 * 24 * 60 * 60;
/// Country header added by Cloudflare.
const COUNTRY_HEADER: &str = "cf-ipcountry";

/// Whether the value is acceptable as a device mark (64 hex characters). Broken values are treated as absent and recreated.
pub fn is_device_token(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A new device mark. Two UUID v4s' worth (OS randomness).
pub fn new_device_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// If the response **newly set** the SSO session cookie, returns its value (responses deleting it excluded).
pub fn issued_sso_session(headers: &HeaderMap) -> Option<String> {
    let base = cookies::SSO_SESSION_COOKIE;
    let prefixed = format!("{}{base}", assay_contracts::cookies::HOST_PREFIX);
    headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|raw| {
            let mut parts = raw.split(';');
            let (name, value) = parts.next()?.trim().split_once('=')?;
            if name != base && name != prefixed {
                return None;
            }
            let expired = parts.any(|attr| {
                let attr = attr.trim().to_ascii_lowercase();
                attr == "max-age=0" || attr.starts_with("expires=thu, 01 jan 1970")
            });
            (!value.is_empty() && !expired).then(|| value.to_string())
        })
}

/// Trustworthy country header (the api checks the format).
pub(crate) fn trusted_country(headers: &HeaderMap, trust_forwarded: bool) -> Option<String> {
    if !trust_forwarded {
        return None;
    }
    headers
        .get(COUNTRY_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

tokio::task_local! {
    /// The current request's browser device mark (task #916). The api client attaches it to internal calls.
    static CLIENT_DEVICE: Option<String>;
}

/// The current request's device mark (`None` outside the middleware or outside a request).
pub fn current_device_token() -> Option<String> {
    CLIENT_DEVICE.try_with(Clone::clone).ok().flatten()
}

/// Whether the response newly set an enrollment ticket (task #916) (responses deleting it excluded).
fn issued_enrollment_ticket(headers: &HeaderMap) -> bool {
    let base = crate::cookies::DEVICE_ENROLLMENT_COOKIE;
    headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|raw| {
            let mut parts = raw.split(';');
            let Some((name, value)) = parts.next().and_then(|p| p.trim().split_once('=')) else {
                return false;
            };
            let name = name
                .strip_prefix(assay_contracts::cookies::HOST_PREFIX)
                .unwrap_or(name);
            name == base
                && !value.is_empty()
                && !parts.any(|attr| attr.trim().eq_ignore_ascii_case("max-age=0"))
        })
}

/// The middleware itself (placed toward the outside of the router, inside `correlation::propagate`).
///
/// The device mark is decided **before the request** (task #916). If absent it is created here and placed in
/// [`current_device_token`] only for the duration of the request. The api decides "is this a registered device"
/// at login time, so the mark must arrive even from a first-time browser. The created mark is set as a cookie only
/// when the response set a signed-in state or an enrollment ticket (not for browsers that merely visited).
pub async fn observe_sign_ins(
    State(state): State<WebState>,
    request: Request,
    next: Next,
) -> Response {
    let existing = cookies::get(request.headers(), DEVICE_COOKIE).filter(|v| is_device_token(v));
    let (token, generated) = match existing {
        Some(token) => (token, false),
        None => (new_device_token(), true),
    };
    let country = trusted_country(request.headers(), state.config.trust_forwarded_headers());
    let user_agent = request
        .headers()
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let ip_address = request
        .extensions()
        .get::<ClientIp>()
        .and_then(|ip| ip.0.clone());
    let correlation_id = request
        .extensions()
        .get::<CorrelationId>()
        .map(|c| c.0.clone())
        .unwrap_or_default();

    // The device-key binding endpoint (task #887) only re-sets the long-lived cookie; it is not a login.
    let key_binding_path = request.uri().path().starts_with("/dbsc/");
    // The SSO session that came with the request. SSO restoration re-sets a cookie with the same value (ADR-0018 decision 4),
    // so binding is requested only when **the value changed** (a new signed-in state). Making Chrome redo
    // registration for the same signed-in state would make the new key "a different key" and end the signed-in state.
    let incoming_sso = cookies::get(request.headers(), cookies::SSO_SESSION_COOKIE);
    let mut response = CLIENT_DEVICE
        .scope(Some(token.clone()), next.run(request))
        .await;
    if key_binding_path {
        return response;
    }
    let issued_sso = issued_sso_session(response.headers());
    if generated && (issued_sso.is_some() || issued_enrollment_ticket(response.headers())) {
        let cookie = state.config.cookie_policy().set_local(
            DEVICE_COOKIE,
            &token,
            DEVICE_COOKIE_MAX_AGE_SECS,
        );
        match HeaderValue::from_str(&cookie) {
            Ok(value) => {
                response.headers_mut().append(SET_COOKIE, value);
            }
            Err(e) => tracing::error!(error = %e, "device cookie is not a valid header value"),
        }
    }
    let Some(sso_session_id) = issued_sso else {
        return response;
    };
    // Ask Chrome to bind the new signed-in state to the device key (DBSC. task #887, ADR-0074).
    let new_session = incoming_sso.as_deref() != Some(sso_session_id.as_str());
    if let Some(value) = new_session
        .then(|| crate::session_key::registration_header(&state, &sso_session_id))
        .flatten()
    {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static(assay_contracts::session_key::REGISTRATION_HEADER),
            value,
        );
    }

    let request = InternalDeviceObserveRequest {
        sso_session_id,
        device_token: Some(token),
        country,
        ip_address,
        user_agent,
    };
    match state.api.device_observe(&correlation_id, &request).await {
        Ok(InternalDeviceObserveResponse::Internal) => {
            tracing::error!("device observation failed in api; the sign-in itself succeeded");
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "device observation call to api failed; the sign-in itself succeeded");
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(SET_COOKIE, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn a_newly_issued_session_cookie_is_found_with_or_without_the_host_prefix() {
        assert_eq!(
            issued_sso_session(&headers(&[
                "lang=ja; Path=/",
                "__Host-sso_session_id=abc; Path=/; HttpOnly; Secure; Max-Age=86400"
            ]))
            .as_deref(),
            Some("abc")
        );
        assert_eq!(
            issued_sso_session(&headers(&["sso_session_id=xyz; Path=/; Max-Age=600"])).as_deref(),
            Some("xyz")
        );
    }

    #[test]
    fn clearing_the_session_cookie_is_not_a_sign_in() {
        assert_eq!(
            issued_sso_session(&headers(&["sso_session_id=; Path=/; Max-Age=0"])),
            None
        );
        assert_eq!(
            issued_sso_session(&headers(&["__Host-sso_session_id=gone; Path=/; Max-Age=0"])),
            None
        );
        assert_eq!(
            issued_sso_session(&headers(&["auth_session_id=abc; Path=/"])),
            None
        );
    }

    #[test]
    fn device_tokens_are_64_hex_characters() {
        let token = new_device_token();
        assert!(is_device_token(&token));
        assert_ne!(token, new_device_token());
        assert!(!is_device_token("short"));
        assert!(!is_device_token(&"z".repeat(64)));
    }

    #[test]
    fn the_country_is_read_only_when_forwarded_headers_are_trusted() {
        let mut h = HeaderMap::new();
        h.insert(COUNTRY_HEADER, HeaderValue::from_static("JP"));
        assert_eq!(trusted_country(&h, true).as_deref(), Some("JP"));
        assert_eq!(trusted_country(&h, false), None);
        h.insert(COUNTRY_HEADER, HeaderValue::from_static(""));
        assert_eq!(trusted_country(&h, true), None);
    }
}
