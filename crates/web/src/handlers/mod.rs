//! web's handlers.

pub mod account_setup;
pub mod admin_accounts_console;
pub mod admin_applications_console;
pub mod admin_authentication_policies_console;
pub mod admin_clients_console;
pub mod admin_console;
pub mod admin_external_idps_console;
pub mod admin_invitations_console;
pub mod admin_login_identifiers_console;
pub mod admin_members_console;
pub mod admin_resources_console;
pub mod admin_restart_console;
pub mod admin_saml_clients_console;
pub mod admin_settings;
pub mod admin_signing_keys_console;
pub mod admin_status_console;
pub mod admin_tenants_console;
pub mod admin_users_console;
pub mod app_approval;
pub mod authenticators;
pub mod consent;
pub mod console_script;
pub mod device_enrollment;
pub mod external_login;
pub mod health;
pub mod invitation_accept;
pub mod login;
pub mod mfa_totp;
pub mod page_scripts;
pub mod passkey;
pub mod password_change;
pub mod password_reset;
pub mod portal;
pub mod react_assets;
pub mod rp_logout;
pub mod saml_sso;
pub mod step_up;
pub mod stylesheet;
pub mod submit_feedback_script;
pub mod user_security;
pub mod user_settings;
pub mod vendor_assets;
pub mod verify_email;
pub mod web_app_manifest;

use crate::api_client::InternalCallError;
use crate::client_ip::ClientIp;
use crate::correlation::CorrelationId;
use crate::i18n::Locale;
use assay_contracts::auth::PasswordRejectionReason;
use axum::http::header::{HeaderValue, ACCEPT_LANGUAGE, LOCATION, USER_AGENT};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

/// Maps a failed `/internal/*` call to the status code returned to the screen (MT28).
///
/// **404 only when the tenant could not be resolved (tenant ID in the URL does not exist or is `DISABLED`).**
/// Aligned with other tenant-prefixed paths (404 returned by the api's `TenantResolver`) — this is
/// a user input error, not a web implementation/configuration error. Before the distinction, merely typing a
/// nonexistent tenant ID made the login submission a bare 502.
///
/// Everything else is 502 as before (api unreachable, broken response, token mismatch).
///
/// The body is filled in by the shared error page middleware ([`crate::error_pages`]), so this
/// only decides the status.
pub(crate) fn internal_call_status(error: &InternalCallError) -> StatusCode {
    match error {
        InternalCallError::UnknownTenant => StatusCode::NOT_FOUND,
        InternalCallError::Failed(_) => StatusCode::BAD_GATEWAY,
    }
}

/// 500 response when the api returns "internal error" as a business result.
///
/// **Always leave one line.** When a request reaching the api fails, the api also records it, but if web's log
/// has only tower_http's "response failed 500", **which internal call failed** is unknown and there is
/// nowhere to start investigating. The TOTP registration 500 on 2026-09-15 was exactly this; getting from the
/// screen symptom to the culprit function burned a lot of time.
///
/// Pass in `call` a short identifier of the internal API called (`totp_setup` etc.). Do not write a human
/// description — every wording fix would break grep.
pub(crate) fn api_internal_error(call: &'static str) -> Response {
    tracing::error!(call, "api reported an internal error");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

/// Decides the display language (MT20).
///
/// Of the decision order (`?lang=` > user setting > cookie > browser language > default `ja`), the top 2 are
/// resolved by the [`crate::display_preferences::resolve_display_preferences`] middleware, which passes the result
/// **normalized into the request's `lang` cookie**. So here it suffices to look at cookie > `Accept-Language` > default `ja`.
///
/// To keep the priority decision in one place (the middleware), handlers do not interpret `?lang=` themselves
/// (interpreting per screen would make priorities diverge as screens are added).
pub(crate) fn locale(headers: &HeaderMap) -> Locale {
    let cookie_lang = crate::cookies::get(headers, crate::cookies::LANG_COOKIE);
    Locale::resolve(
        None,
        None,
        cookie_lang.as_deref(),
        headers.get(ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()),
    )
}

/// Maps `?error=` of a form page returned via PRG (Post/Redirect/Get) to the error banner's translation key.
/// A POST with a CSRF mismatch is switched by 303 to a GET with `?error=csrf`, automatically re-showing a form with a
/// new token (returning an error page as the POST response would make reload a resubmission with no recovery).
pub(crate) fn form_retry_error_key(error: Option<&str>) -> Option<&'static str> {
    match error {
        Some("csrf") => Some("login-error-csrf-retry"),
        _ => None,
    }
}

/// Maps the reason a password was rejected (AP7) to the wording key shown on screen.
///
/// Only length etc. (`Policy`) has existing per-screen keys, so it is received from the caller; breached and
/// reused use **keys shared by all screens**. Different wording per reason because the user's next
/// action differs (make it longer / think of another value).
pub(crate) fn password_rejection_key(
    reason: PasswordRejectionReason,
    policy_key: &'static str,
) -> &'static str {
    match reason {
        PasswordRejectionReason::Policy => policy_key,
        PasswordRejectionReason::Breached => "password-error-breached",
        PasswordRejectionReason::Reused => "password-error-reused",
    }
}

/// Maps the above to the `?error=` code of a PRG redirect (for screens that return without re-showing the form).
pub(crate) fn password_rejection_error_code(
    reason: PasswordRejectionReason,
    policy_code: &'static str,
) -> &'static str {
    match reason {
        PasswordRejectionReason::Policy => policy_code,
        PasswordRejectionReason::Breached => "breached",
        PasswordRejectionReason::Reused => "reused",
    }
}

/// Connection origin information forwarded to internal authentication calls.
pub(crate) struct ForwardedContext {
    pub correlation_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Builds the connection origin information forwarded to the api.
///
/// The IP is **not read from headers here**. Deciding whether `X-Forwarded-For` may be trusted
/// (`TRUST_FORWARDED_HEADERS`) and falling back to the peer address are done centrally by the
/// [`crate::client_ip::resolve_client_ip`] middleware, which passes the result as `Extension<ClientIp>`
/// (SEC1). Reading headers per handler would mix in forgotten gates.
pub(crate) fn forwarded_context(
    headers: &HeaderMap,
    correlation: &CorrelationId,
    client_ip: &ClientIp,
) -> ForwardedContext {
    let ip_address = client_ip.0.clone();
    let user_agent = headers
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    ForwardedContext {
        correlation_id: correlation.0.clone(),
        ip_address,
        user_agent,
    }
}

/// `302 Found` redirect (design spec §4.2. axum's `Redirect::to` is 303, so it is not used).
pub(crate) fn found(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(value) => (StatusCode::FOUND, [(LOCATION, value)]).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "redirect location is not a valid header value");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `303 See Other` redirect. Used for the switch to our own URL that immediately removes the hand-off URL's
/// single-use handle (`?auth_session=`) from the address bar and history (ADR-0018 decision 2).
pub(crate) fn see_other(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(value) => (StatusCode::SEE_OTHER, [(LOCATION, value)]).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "redirect location is not a valid header value");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::subscriber::with_default;
    use tracing::{Event, Level, Subscriber};
    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::registry::LookupSpan;

    /// Layer collecting the `call` field of ERROR events.
    #[derive(Clone, Default)]
    struct CallCollector(Arc<Mutex<Vec<String>>>);

    impl<S> Layer<S> for CallCollector
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            if *event.metadata().level() != Level::ERROR {
                return;
            }
            struct Grab<'a>(&'a mut Option<String>);
            impl Visit for Grab<'_> {
                fn record_debug(&mut self, _f: &Field, _v: &dyn std::fmt::Debug) {}
                fn record_str(&mut self, f: &Field, v: &str) {
                    if f.name() == "call" {
                        *self.0 = Some(v.to_string());
                    }
                }
            }
            let mut call = None;
            event.record(&mut Grab(&mut call));
            if let Some(call) = call {
                self.0.lock().expect("collector").push(call);
            }
        }
    }

    /// **Do not return 500 silently.** If all web's log keeps when the api returns an internal error is
    /// tower_http's "response failed 500", which internal call failed is unknown, and there is no
    /// clue from the screen symptom to the cause (the TOTP registration 500 on 2026-09-15).
    #[test]
    fn reporting_an_api_internal_error_names_the_failing_call() {
        let collector = CallCollector::default();
        let subscriber = tracing_subscriber::registry().with(collector.clone());

        let response = with_default(subscriber, || api_internal_error("totp_setup"));

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let calls = collector.0.lock().expect("collector").clone();
        assert_eq!(calls, vec!["totp_setup".to_string()]);
    }

    /// **Guard against adding more branches that silently return 500.**
    ///
    /// There were 27 places mapping the api's `Internal` to 500, and none of them logged.
    /// Fixing them one by one, the next new branch opens the same hole. The source is inspected for the
    /// same reason as the route list (`router::declared_route_paths`) — so a separate list does not
    /// diverge from the real thing.
    #[test]
    fn every_internal_result_that_becomes_a_500_says_which_call_failed() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handlers");
        let mut offenders = Vec::new();
        let mut checked = 0usize;
        for entry in std::fs::read_dir(&dir).expect("read handlers dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read handler source");
            // Test-only code (containing the strings this check itself holds) is excluded. Same cut as
            // the route list check in `router.rs`.
            let source = source.split("#[cfg(test)]").next().unwrap_or_default();
            let lines: Vec<&str> = source.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if !(line.contains("Response::Internal") && line.contains("=>")) {
                    continue;
                }
                let window = lines[i..lines.len().min(i + 5)].join("\n");
                if !window.contains("INTERNAL_SERVER_ERROR")
                    && !window.contains("api_internal_error")
                {
                    // Branches mapping to something other than 500 (JSON paths etc.) are excluded.
                    continue;
                }
                checked += 1;
                if !window.contains("api_internal_error") && !window.contains("tracing::error!") {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
                    offenders.push(format!("{name}:{}", i + 1));
                }
            }
        }
        assert!(checked > 20, "lost track of the targets ({checked} found)");
        assert!(
            offenders.is_empty(),
            "some places silently turn api internal errors into 500 (route them through `api_internal_error`): {offenders:?}"
        );
    }
}
