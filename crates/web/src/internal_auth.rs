//! Middleware protecting web's own `/internal/*` (ADR-0031).
//!
//! Uses the same header and the same check as the api (`assay_contracts::internal_auth`). Since web, as
//! the caller of the api, already holds the same token, no new secret is added.
//!
//! web needs an internal surface too because **the api cannot know web's own state** (version, start time,
//! reachability of the api). Looking at the api's `/internal/health` cannot tell whether web is alive.

use crate::state::WebState;
use assay_contracts::internal_auth::{service_token_matches, SERVICE_TOKEN_HEADER};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Protects `/internal/*`. Blocks with 401 if the token does not match.
///
/// The response gives no reason so as not to reveal whether the token is "missing" or "wrong".
pub async fn require_service_token(
    State(state): State<WebState>,
    request: Request,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get(SERVICE_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !service_token_matches(presented, state.config.internal_service_token()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(request).await
}
