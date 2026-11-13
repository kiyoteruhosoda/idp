//! The "you are not allowed to use this application" screen (decision 2 of ADR-0054).
//!
//! The decision is made in **one place, at code issuance** (api's `CodeIssuanceService`), but there are
//! 7 paths that reach it: sign-in, MFA, passkey, external IdP, password change, consent, and SSO resume.
//! SAML gets the same decision at the point where the assertion is issued (api's `SamlSsoService::resume`).
//! Whichever path the user came from, they see the same screen, so the rendering lives only here.
//!
//! ⚠ **Do not redirect to the RP.** The refusal is communicated on assay's screen. Sending the user back to the RP
//! only looks like "I signed in and got thrown onto the app's error page", and nothing anywhere tells them
//! what to do next.

use crate::i18n::Messages;
use crate::templates::{render, ApplicationNotPermittedPage};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

/// Renders the refusal screen.
///
/// `tenant_prefix` is the `/{tenant_id}` used to build the way back (the user's own account screen).
/// If empty, no link is shown — the error screen should not be a dead end, but it also must not link
/// to a place the user cannot go.
pub fn page(messages: &Messages, tenant_prefix: &str, application_name: &str) -> Response {
    let body = render(&ApplicationNotPermittedPage {
        lang: messages.lang(),
        title: messages.get("application-not-permitted-title"),
        signed_in: messages.get_arg(
            "application-not-permitted-signed-in",
            "application",
            application_name,
        ),
        next_step: messages.get_arg(
            "application-not-permitted-next-step",
            "application",
            application_name,
        ),
        back_href: if tenant_prefix.is_empty() {
            String::new()
        } else {
            format!("{tenant_prefix}/settings")
        },
        back_label: messages.get("application-not-permitted-back"),
    });
    // 403. Authentication succeeded, so not 401 — "we know who you are, but you cannot use this".
    (StatusCode::FORBIDDEN, Html(body)).into_response()
}
