//! Holds the "trusted country" attached by web, only for the duration of an internal request (task #895).
//!
//! web trusts `CF-IPCountry` only under `TRUST_FORWARDED_HEADERS` and attaches it to internal calls as
//! [`CLIENT_COUNTRY_HEADER`]. This middleware is attached **only to the `/internal/*` subrouter**
//! (behind the service token). The same header on requests hitting the api directly can be set by anyone, so it is not read.
//!
//! Only the copy of rejected sign-in history (`SignInFailureRecordingSink`) reads it, passed as [`RequestCountry`].

use crate::domain::sign_in_history::RequestCountry;
use crate::domain::user_device::CountryCode;
use assay_contracts::auth::CLIENT_COUNTRY_HEADER;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

tokio::task_local! {
    static CLIENT_COUNTRY: Option<CountryCode>;
}

/// Holds the country attached by web, only for the duration of an internal request.
pub async fn capture_client_country(request: Request, next: Next) -> Response {
    let country = request
        .headers()
        .get(CLIENT_COUNTRY_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(CountryCode::parse);
    CLIENT_COUNTRY.scope(country, next.run(request)).await
}

/// Accessor for the current request's country (`None` outside a request or for external requests).
pub struct TaskLocalRequestCountry;

impl RequestCountry for TaskLocalRequestCountry {
    fn current(&self) -> Option<CountryCode> {
        CLIENT_COUNTRY.try_with(Clone::clone).ok().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_country_is_visible_only_inside_the_scope() {
        assert_eq!(TaskLocalRequestCountry.current(), None);
        let inside = CLIENT_COUNTRY
            .scope(CountryCode::parse("JP"), async {
                TaskLocalRequestCountry.current()
            })
            .await;
        assert_eq!(inside.as_ref().map(CountryCode::as_str), Some("JP"));
        assert_eq!(TaskLocalRequestCountry.current(), None);
    }
}
