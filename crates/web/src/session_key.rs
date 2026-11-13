//! Binding the SSO session to the device key (Chrome's DBSC. task #887. ADR-0074), web side.
//!
//! | Role | What it does |
//! |---|---|
//! | [`registration_header`] | Adds `Secure-Session-Registration` to the login response (the one that set the SSO session cookie) |
//! | [`register`] (`POST /dbsc/register`) | Passes Chrome's signature to the api and issues the short cookie once bound |
//! | [`refresh`] (`POST /dbsc/refresh`) | Refresh when the short cookie expires. Without a signature, hands a challenge with 403 |
//! | [`enforce`] (middleware) | For requests without a matching short cookie, strips the long cookie if the signed-in state is bound |
//!
//! The rules (header names, JSON shapes) follow the W3C WebAppSec draft (2026-09-08 version) and Chrome's documents.

use crate::client_ip::ClientIp;
use crate::cookies::{self, SSO_SESSION_COOKIE};
use crate::correlation::CorrelationId;
use crate::state::WebState;
use assay_contracts::auth::{
    InternalSessionKeyBindingRequest, InternalSessionKeyBindingResponse,
    InternalSessionKeyRefreshRequest, InternalSessionKeyRegisterRequest,
    InternalSessionKeyResponse,
};
use assay_contracts::session_key as contract;
use axum::extract::{Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, SET_COOKIE, USER_AGENT};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long the answer to "is it bound" is remembered.
const BINDING_CACHE_TTL: Duration = Duration::from_secs(60);
/// Maximum number of remembered entries (oldest are dropped beyond it).
const BINDING_CACHE_MAX: usize = 10_000;

/// Briefly remembers the answer to "is this SSO session bound" (so the entry point does not call the api every time).
///
/// The key is the SHA-256 of the SSO session cookie (no plaintext kept). Binding only changes from "no → yes", so
/// remembering "no" for 60 s lets the long cookie alone pass for 60 s right after binding (meanwhile Chrome has
/// received the short cookie).
#[derive(Clone, Default)]
pub struct SessionKeyCache {
    entries: Arc<Mutex<HashMap<String, (bool, Instant)>>>,
}

impl SessionKeyCache {
    fn get(&self, key: &str) -> Option<bool> {
        let entries = self.entries.lock().ok()?;
        entries
            .get(key)
            .filter(|(_, at)| at.elapsed() < BINDING_CACHE_TTL)
            .map(|(bound, _)| *bound)
    }

    fn put(&self, key: String, bound: bool) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if entries.len() >= BINDING_CACHE_MAX {
            entries.retain(|_, (_, at)| at.elapsed() < BINDING_CACHE_TTL);
            if entries.len() >= BINDING_CACHE_MAX {
                entries.clear();
            }
        }
        entries.insert(key, (bound, Instant::now()));
    }

    /// Re-remember when it is known to be bound (right after registration).
    pub fn mark_bound(&self, sso_session_id: &str) {
        self.put(cache_key(sso_session_id), true);
    }
}

fn cache_key(sso_session_id: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(sso_session_id.as_bytes()))
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// `Secure-Session-Registration` added to the login response (built from the value of the newly set SSO session cookie).
pub fn registration_header(state: &WebState, sso_session_id: &str) -> Option<HeaderValue> {
    let challenge = contract::challenge(state.config.csrf_secret(), sso_session_id, now_secs());
    HeaderValue::from_str(&contract::registration_header(&challenge)).ok()
}

/// Browser-side name of the short cookie (prefixed with `__Host-` over HTTPS).
fn bound_cookie_name(state: &WebState) -> String {
    state
        .config
        .cookie_policy()
        .origin_bound_name(contract::BOUND_COOKIE)
}

/// Expiry (UNIX seconds) of this browser's short cookie. `None` if missing, mismatched or expired (task #896).
pub fn bound_cookie_expiry(
    state: &WebState,
    headers: &axum::http::HeaderMap,
    sso_session_id: &str,
) -> Option<i64> {
    let value = crate::cookies::get(headers, &bound_cookie_name(state))?;
    contract::bound_cookie_expires_at(
        state.config.csrf_secret(),
        sso_session_id,
        &value,
        now_secs(),
    )
}

/// `Set-Cookie` setting the short cookie.
fn set_bound_cookie(state: &WebState, sso_session_id: &str) -> String {
    let expires_at = now_secs() + contract::BOUND_COOKIE_MAX_AGE_SECS;
    let value = contract::bound_cookie(state.config.csrf_secret(), sso_session_id, expires_at);
    state.config.cookie_policy().set_local(
        &bound_cookie_name(state),
        &value,
        contract::BOUND_COOKIE_MAX_AGE_SECS as u64,
    )
}

/// Attributes of the short cookie (written in the registration response's `credentials`; Chrome identifies the cookie by them and ignores Max-Age).
fn bound_cookie_attributes(state: &WebState) -> String {
    let mut attributes = "Path=/; HttpOnly; SameSite=Lax".to_string();
    if state.config.cookie_policy().secure() {
        attributes.push_str("; Secure");
    }
    attributes
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

struct Caller {
    correlation_id: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

fn caller(request: &Request) -> Caller {
    Caller {
        correlation_id: request
            .extensions()
            .get::<CorrelationId>()
            .map(|c| c.0.clone())
            .unwrap_or_default(),
        ip_address: request
            .extensions()
            .get::<ClientIp>()
            .and_then(|ip| ip.0.clone()),
        user_agent: header_str(request.headers(), USER_AGENT.as_str()).map(str::to_string),
    }
}

/// JSON response (not cacheable).
fn json_response(status: StatusCode, body: serde_json::Value) -> Response {
    let mut response = (status, body.to_string()).into_response();
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// "Binding of this signed-in state is over" (Chrome discards the binding).
fn terminated() -> Response {
    json_response(StatusCode::OK, serde_json::json!({ "continue": false }))
}

fn append_cookie(response: &mut Response, cookie: &str) {
    match HeaderValue::from_str(cookie) {
        Ok(value) => {
            response.headers_mut().append(SET_COOKIE, value);
        }
        Err(e) => tracing::error!(error = %e, "session key cookie is not a valid header value"),
    }
}

/// Adds the short cookie and the re-set long cookie (with remaining lifetime) to a response where binding continues.
fn add_bound_cookies(
    state: &WebState,
    response: &mut Response,
    sso_session_id: &str,
    remaining_secs: u64,
) {
    append_cookie(response, &set_bound_cookie(state, sso_session_id));
    for cookie in
        state
            .config
            .cookie_policy()
            .set_session(SSO_SESSION_COOKIE, sso_session_id, remaining_secs)
    {
        append_cookie(response, &cookie);
    }
}

/// Also deletes the browser's cookies when the signed-in state is ended.
fn expire_cookies(state: &WebState, response: &mut Response) {
    let policy = state.config.cookie_policy();
    append_cookie(response, &policy.expire_local(&bound_cookie_name(state)));
    for cookie in policy.expire_session(SSO_SESSION_COOKIE) {
        append_cookie(response, &cookie);
    }
}

/// Body of the registration and refresh responses (binding configuration; draft §9.6).
///
/// The scope is only assay's origin (`include_site: false`). The configured host patterns go into
/// `allowed_refresh_initiators` so Chrome re-fetches the short cookie even for requests started from apps (hidden-frame `prompt=none`) (task #934).
fn session_instructions(state: &WebState, session_identifier: &str) -> serde_json::Value {
    serde_json::json!({
        "session_identifier": session_identifier,
        "refresh_url": contract::REFRESH_PATH,
        "scope": {
            "include_site": false,
            "scope_specification": [],
        },
        "credentials": [{
            "type": "cookie",
            "name": bound_cookie_name(state),
            "attributes": bound_cookie_attributes(state),
        }],
        "allowed_refresh_initiators": state.config.dbsc_allowed_refresh_initiators(),
    })
}

/// Registration (`POST /dbsc/register`).
pub async fn register(State(state): State<WebState>, request: Request) -> Response {
    let who = caller(&request);
    let headers = request.headers();
    let (Some(sso_session_id), Some(proof)) = (
        cookies::get(headers, SSO_SESSION_COOKIE),
        header_str(headers, contract::RESPONSE_HEADER).map(str::to_string),
    ) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let req = InternalSessionKeyRegisterRequest {
        sso_session_id: sso_session_id.clone(),
        proof,
        ip_address: who.ip_address,
        user_agent: who.user_agent,
    };
    match state
        .api
        .session_key_register(&who.correlation_id, &req)
        .await
    {
        Ok(InternalSessionKeyResponse::Bound {
            session_identifier,
            remaining_secs,
        }) => {
            state.session_keys.mark_bound(&sso_session_id);
            let mut response = json_response(
                StatusCode::OK,
                session_instructions(&state, &session_identifier),
            );
            add_bound_cookies(&state, &mut response, &sso_session_id, remaining_secs);
            response
        }
        Ok(InternalSessionKeyResponse::KeyMismatch) => {
            let mut response = StatusCode::BAD_REQUEST.into_response();
            expire_cookies(&state, &mut response);
            response
        }
        Ok(InternalSessionKeyResponse::Internal) | Err(_) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// Refresh (`POST /dbsc/refresh`).
pub async fn refresh(State(state): State<WebState>, request: Request) -> Response {
    let who = caller(&request);
    let headers = request.headers();
    let Some(sso_session_id) = cookies::get(headers, SSO_SESSION_COOKIE) else {
        return terminated();
    };
    let Some(session_identifier) = header_str(headers, contract::SESSION_ID_HEADER)
        .filter(|v| contract::is_session_identifier(v))
        .map(str::to_string)
    else {
        return terminated();
    };
    let Some(proof) = header_str(headers, contract::RESPONSE_HEADER).map(str::to_string) else {
        // First attempt without a signature: hand out a challenge (checking first that the binding is still alive).
        return challenge_or_end(&state, &who, &sso_session_id, &session_identifier).await;
    };
    let req = InternalSessionKeyRefreshRequest {
        sso_session_id: sso_session_id.clone(),
        session_identifier: session_identifier.clone(),
        proof,
        ip_address: who.ip_address.clone(),
        user_agent: who.user_agent.clone(),
    };
    match state
        .api
        .session_key_refresh(&who.correlation_id, &req)
        .await
    {
        Ok(InternalSessionKeyResponse::Bound { remaining_secs, .. }) => {
            // Return the same configuration as registration. Per the draft (§8.8, §8.9) a refresh response with a body replaces the binding config,
            // so signed-in states bound before the config was added also receive `allowed_refresh_initiators` at the next refresh.
            let mut response = json_response(
                StatusCode::OK,
                session_instructions(&state, &session_identifier),
            );
            add_bound_cookies(&state, &mut response, &sso_session_id, remaining_secs);
            response
        }
        // Stale challenge etc.: try again with a new challenge.
        Ok(InternalSessionKeyResponse::Rejected) => {
            challenge_response(&state, &sso_session_id, &session_identifier)
        }
        Ok(InternalSessionKeyResponse::KeyMismatch) => {
            let mut response = terminated();
            expire_cookies(&state, &mut response);
            response
        }
        Ok(InternalSessionKeyResponse::SessionGone) => terminated(),
        // Transient failure. Chrome keeps the binding and retries later.
        Ok(InternalSessionKeyResponse::Internal) | Err(_) => {
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

async fn challenge_or_end(
    state: &WebState,
    who: &Caller,
    sso_session_id: &str,
    session_identifier: &str,
) -> Response {
    let req = InternalSessionKeyBindingRequest {
        sso_session_id: sso_session_id.to_string(),
    };
    match state
        .api
        .session_key_binding(&who.correlation_id, &req)
        .await
    {
        Ok(InternalSessionKeyBindingResponse::Bound {
            session_identifier: bound,
        }) if bound == session_identifier => {
            challenge_response(state, sso_session_id, session_identifier)
        }
        Ok(InternalSessionKeyBindingResponse::Internal) | Err(_) => {
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        Ok(_) => terminated(),
    }
}

fn challenge_response(
    state: &WebState,
    sso_session_id: &str,
    session_identifier: &str,
) -> Response {
    let challenge = contract::challenge(state.config.csrf_secret(), sso_session_id, now_secs());
    let mut response = StatusCode::FORBIDDEN.into_response();
    match HeaderValue::from_str(&contract::challenge_header(&challenge, session_identifier)) {
        Ok(value) => {
            response
                .headers_mut()
                .insert(HeaderName::from_static(contract::CHALLENGE_HEADER), value);
        }
        Err(e) => tracing::error!(error = %e, "session challenge is not a valid header value"),
    }
    response
}

/// Entry-point check (middleware). Placed inside `bind_session_cookie_names` and outside handlers.
///
/// For requests with a long cookie but no matching short cookie, if that signed-in state is bound, the long cookie is
/// removed from the request (every screen sees "not signed in"). `/dbsc/*` (registration/refresh itself) and
/// `/assets/*` are skipped. It is also removed when the api could not be asked (do not pass what may be bound).
pub async fn enforce(State(state): State<WebState>, mut request: Request, next: Next) -> Response {
    let path = request.uri().path();
    if path.starts_with("/dbsc/") || path.starts_with("/assets/") {
        return next.run(request).await;
    }
    let Some(sso_session_id) = cookies::get(request.headers(), SSO_SESSION_COOKIE) else {
        return next.run(request).await;
    };
    if let Some(bound) = cookies::get(request.headers(), &bound_cookie_name(&state)) {
        if contract::bound_cookie_is_valid(
            state.config.csrf_secret(),
            &sso_session_id,
            &bound,
            now_secs(),
        ) {
            return next.run(request).await;
        }
    }
    let key = cache_key(&sso_session_id);
    let bound = match state.session_keys.get(&key) {
        Some(bound) => bound,
        None => {
            let correlation_id = caller(&request).correlation_id;
            let req = InternalSessionKeyBindingRequest {
                sso_session_id: sso_session_id.clone(),
            };
            match state.api.session_key_binding(&correlation_id, &req).await {
                Ok(InternalSessionKeyBindingResponse::Bound { .. }) => {
                    state.session_keys.put(key, true);
                    true
                }
                Ok(InternalSessionKeyBindingResponse::Unbound) => {
                    state.session_keys.put(key, false);
                    false
                }
                Ok(InternalSessionKeyBindingResponse::Internal) | Err(_) => {
                    tracing::error!(
                        "session key binding could not be checked; treating the session as absent"
                    );
                    true
                }
            }
        }
    };
    if bound {
        strip_session_cookie(request.headers_mut());
    }
    next.run(request).await
}

/// Removes the SSO session cookie from the `Cookie` header (by the mapped name; prefixed names are already mapped).
fn strip_session_cookie(headers: &mut HeaderMap) {
    let kept: Vec<String> = headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|raw| raw.split(';'))
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .filter(|pair| pair.split_once('=').map_or(*pair, |(k, _)| k) != SSO_SESSION_COOKIE)
        .map(str::to_string)
        .collect();
    headers.remove(COOKIE);
    if kept.is_empty() {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(&kept.join("; ")) {
        headers.insert(COOKIE, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stripping_removes_only_the_session_cookie() {
        let mut headers = HeaderMap::new();
        headers.append(
            COOKIE,
            HeaderValue::from_static("lang=ja; sso_session_id=abc; assay_device=d"),
        );
        headers.append(COOKIE, HeaderValue::from_static("theme=dark"));
        strip_session_cookie(&mut headers);
        let rebuilt = headers.get(COOKIE).unwrap().to_str().unwrap();
        assert_eq!(rebuilt, "lang=ja; assay_device=d; theme=dark");
        assert_eq!(cookies::get(&headers, SSO_SESSION_COOKIE), None);
    }

    #[test]
    fn stripping_the_only_cookie_leaves_no_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_static("sso_session_id=abc"));
        strip_session_cookie(&mut headers);
        assert!(headers.get(COOKIE).is_none());
    }

    #[test]
    fn the_cache_remembers_answers_for_a_while() {
        let cache = SessionKeyCache::default();
        assert_eq!(cache.get(&cache_key("s")), None);
        cache.put(cache_key("s"), false);
        assert_eq!(cache.get(&cache_key("s")), Some(false));
        cache.mark_bound("s");
        assert_eq!(cache.get(&cache_key("s")), Some(true));
    }
}
