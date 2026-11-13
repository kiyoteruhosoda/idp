//! Restart from the admin console (web. `POST /{tenant_id}/admin/restart`. ADR-0017).
//!
//! DB overrides of runtime settings are read only at startup (ADR-0014). So that operators need not go
//! to a shell just to apply them, the settings screen can restart **api first, then web**.
//!
//! The order cannot be reversed. web receives the shared runtime settings from the api at startup (ADR-0013),
//! so if web came up first it would pick up stale values served by the not-yet-restarted api. Therefore
//!
//! 1. request a restart from the api and **confirm it was accepted**,
//! 2. return the restarting screen,
//! 3. stop web itself after that response has been fully sent,
//!
//! in that order. If the api request fails, web is not stopped (if only web went down, the screens would
//! vanish while the api is running, removing the very means of ordering a restart).
//!
//! Starting the new process is the deployment's restart policy (see `service_restart`). In an environment
//! without such a policy the service stays stopped, so the screen always states that premise before running.

use super::locale;
use crate::api_client::AdminApiError;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_valid;
use crate::dto::AdminRestartForm;
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminResolution,
};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, Restarting};
use crate::tenant::WebTenant;
use crate::{cookies, service_restart::ServiceRestart};
use axum::extract::{Extension, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use std::time::Duration;

const SETTINGS_SEGMENT: &str = "/admin/settings";

/// Grace period between returning the waiting screen and stopping web.
///
/// The api starts stopping about 0.5 s after accepting. If web went down earlier, the waiting screen could not
/// finish rendering, and web might restart first and pick up stale shared settings. Set it so as not to overtake the api's stop.
const WEB_SHUTDOWN_DELAY: Duration = Duration::from_secs(2);

/// Seconds until the waiting screen automatically returns to the settings screen. Long enough for both services
/// to start (web includes retries to the api). Too short gives "back but erroring", indistinguishable from a failed restart.
const RETRY_AFTER_SECONDS: u64 = 20;

/// Restarts the api and web.
pub async fn restart(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminRestartForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{SETTINGS_SEGMENT}", tenant.prefix());
    let sso = cookies::get(&headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }

    // 1. Stop the api first (web is not stopped until accepted).
    if let Err(e) = state
        .api
        .request_restart(&correlation.0, &tenant.0, &sso)
        .await
    {
        return match e {
            AdminApiError::Unauthorized => redirect_to_login(&tenant),
            AdminApiError::Forbidden => forbidden_response(&headers),
            other => {
                tracing::error!(error = %other, "failed to request an api restart");
                found(&format!("{base}?error=restart#runtime-settings"))
            }
        };
    }

    // 2. Schedule web's own stop. Stopping before the response is fully sent would lose the waiting screen.
    schedule_web_shutdown(state.restart.clone());

    // 3. Waiting screen (automatically returns to the settings screen).
    let messages = Messages::new(locale(&headers));
    Html(render(&Restarting {
        messages: &messages,
        settings_href: &base,
        retry_after_seconds: RETRY_AFTER_SECONDS,
    }))
    .into_response()
}

fn schedule_web_shutdown(restart: ServiceRestart) {
    tokio::spawn(async move {
        tokio::time::sleep(WEB_SHUTDOWN_DELAY).await;
        tracing::warn!("restarting the web service after the api restart request");
        restart.request();
    });
}
