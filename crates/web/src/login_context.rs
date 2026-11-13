//! Context that an in-progress authorization request brings to the login screen (`login_hint` / `ui_locales`. G12).
//!
//! These parameters received by `/authorize` are stored in the api's auth_session, but web drops the state
//! with the resume 303 (the switch removing the single-use handle from the URL), so they are not at hand
//! when rendering. Here, **only for requests carrying the host-only `auth_session_id` cookie**, they are re-fetched
//! from the api's `/internal/authorize/login-context` and passed downstream via `Extension`.
//!
//! It lives in middleware because there are two consumers. `ui_locales` is used for deciding the display language
//! ([`crate::display_preferences`]), and `login_hint` and the display names (client name, tenant name) by the login
//! screen handler. Fetching in the handler would come after the language decision and cause mismatches like
//! "screen in English, wording in Japanese", or fetch the same context twice. Fetch once, and leave the ordering
//! decision to [`crate::display_preferences`].
//!
//! The cost is **one request to the api per screen render during an OIDC flow** (a local hop).
//! The `auth_session_id` cookie exists only during login, consent, MFA and forced password change,
//! so admin console and portal screens have no extra cost. A fetch failure does not break the screen (renders without context).

use crate::cookies;
use crate::correlation::CorrelationId;
use crate::state::WebState;
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalAuthorizeLoginContextRequest, InternalAuthorizeLoginContextResponse,
};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

/// Display hints brought by an in-progress authorization request. Passed via `Extension` to downstream handlers/middleware.
///
/// `login_hint` is **an arbitrary string specified by the RP** and does not imply an existing account.
/// It is a value for display and is not used for authentication/authorization decisions.
#[derive(Debug, Clone, Default)]
pub struct RpLoginContext {
    pub login_hint: Option<String>,
    pub ui_locales: Option<String>,
    /// The in-progress authorization request's `redirect_uri`. Source of the origin allowed in the login screen's
    /// CSP `form-action` (`security_headers::csp_allowing_form_action`). `None` outside an OIDC flow.
    pub redirect_uri: Option<String>,
    /// Display name of the client that made the authorization request (looked up by the api from the registered
    /// `Clients.app_name`; **not the RP's claim**). Shown in the login screen heading to indicate which app is being entered.
    pub client_name: Option<String>,
    /// Display name of the flow's tenant. Shown in the login screen's navbar to indicate which organization's account is used.
    pub tenant_name: Option<String>,
}

/// Middleware that re-fetches the authorization request context into `Extension` if there is an `auth_session_id` cookie.
///
/// Placed inside [`crate::tenant::capture_tenant`] and outside [`crate::display_preferences::resolve_display_preferences`]
/// (it needs the tenant, and the language decision reads the result).
/// Even without context (outside an OIDC flow, fetch failure) an empty value is attached. Downstream can always
/// receive `Extension<RpLoginContext>`.
pub async fn load_rp_login_context(
    State(state): State<WebState>,
    mut request: Request,
    next: Next,
) -> Response {
    // References to the request cannot live across an await (`axum::body::Body` is not `Sync`, so
    // `&Request` is not `Send`). Extract only the needed values first.
    let identifiers = cookies::get(request.headers(), cookies::AUTH_SESSION_COOKIE).zip(
        request
            .extensions()
            .get::<WebTenant>()
            .map(|tenant| tenant.0.clone()),
    );
    let correlation_id = request
        .extensions()
        .get::<CorrelationId>()
        .map(|c| c.0.clone())
        .unwrap_or_default();

    let context = match identifiers {
        Some((auth_session_id, tenant_id)) => {
            fetch(&state, &correlation_id, tenant_id, auth_session_id).await
        }
        // Outside an OIDC flow (no `auth_session_id` cookie). The api is not called.
        None => None,
    };
    request.extensions_mut().insert(context.unwrap_or_default());
    next.run(request).await
}

/// Fetches the context. `None` on fetch failure or expiry.
async fn fetch(
    state: &WebState,
    correlation_id: &str,
    tenant_id: String,
    auth_session_id: String,
) -> Option<RpLoginContext> {
    let req = InternalAuthorizeLoginContextRequest {
        tenant_id: Some(tenant_id),
        auth_session_id,
    };
    match state
        .api
        .authorize_login_context(correlation_id, &req)
        .await
    {
        Ok(InternalAuthorizeLoginContextResponse::Ok {
            login_hint,
            ui_locales,
            redirect_uri,
            client_name,
            tenant_name,
        }) => Some(RpLoginContext {
            login_hint,
            ui_locales,
            redirect_uri,
            client_name,
            tenant_name,
        }),
        // Just a leftover expired cookie. Render without context and leave expiry to the handler's path.
        Ok(InternalAuthorizeLoginContextResponse::SessionExpired) => None,
        // Rendering on without context is intended, but **the cost is no longer just a missing login_hint**.
        // Without `redirect_uri`, the RP's origin cannot be added to the login screen's CSP, and the browser blocks
        // the navigation to the RP after successful login (SEC3). It fails with nothing abnormal on screen or in
        // server logs, so record it here naming the consequence.
        Ok(InternalAuthorizeLoginContextResponse::Internal) => {
            tracing::warn!(
                consequence = "login page falls back to the default CSP; the redirect to the RP will be blocked",
                "api could not read the authorization request context"
            );
            None
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                consequence = "login page falls back to the default CSP; the redirect to the RP will be blocked",
                "could not read the authorization request context"
            );
            None
        }
    }
}
