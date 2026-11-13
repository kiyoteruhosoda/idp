//! Holds the request's "trustworthy country" for the duration of that request only (task #895).
//!
//! The country (`CF-IPCountry`) is trusted only when `TRUST_FORWARDED_HEADERS` is enabled (same
//! check as [`crate::device_observation`]). The middleware places it here for the duration of the
//! request, and the api client attaches it to internal calls as
//! [`assay_contracts::auth::CLIENT_COUNTRY_HEADER`]. api writes the country into the history of
//! refused sign-ins.
//!
//! It is not passed as a handler argument because every sign-in path (password, verification code,
//! passkey, external IdP, admin console, password change) only calls api, and only the history on
//! the api side needs the country. Adding a field to each path's DTO would drop the country on
//! exactly the path where it was forgotten.

use crate::device_observation::trusted_country;
use crate::state::WebState;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

tokio::task_local! {
    static CLIENT_COUNTRY: Option<String>;
}

/// The current request's trustworthy country (`None` outside the middleware or outside a request).
pub fn current() -> Option<String> {
    CLIENT_COUNTRY.try_with(Clone::clone).ok().flatten()
}

/// Middleware that holds the country for the duration of the request.
pub async fn scope_client_country(
    State(state): State<WebState>,
    request: Request,
    next: Next,
) -> Response {
    // It goes into a header, so only country-code shapes (2 alphanumerics) are kept (a broken
    // header must not fail the api call).
    let country = trusted_country(request.headers(), state.config.trust_forwarded_headers())
        .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphanumeric()));
    CLIENT_COUNTRY.scope(country, next.run(request)).await
}

/// For tests: runs `f` with a country set.
#[cfg(test)]
pub async fn with_country<F: std::future::Future>(country: Option<String>, f: F) -> F::Output {
    CLIENT_COUNTRY.scope(country, f).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_country_is_only_visible_inside_the_request() {
        assert_eq!(current(), None);
        let inside = with_country(Some("JP".to_string()), async { current() }).await;
        assert_eq!(inside.as_deref(), Some("JP"));
        assert_eq!(current(), None);
    }
}
