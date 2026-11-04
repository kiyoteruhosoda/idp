//! web が添えた「信じてよい国」を、内部の要求の間だけ持つ（task #895）。
//!
//! web は `CF-IPCountry` を `TRUST_FORWARDED_HEADERS` のときだけ信じ、内部の呼び出しに
//! [`CLIENT_COUNTRY_HEADER`] として添える。この middleware は **`/internal/*` のサブルータにだけ**付ける
//! （サービストークンの内側）。外から直接 api に来た要求の同じ見出しは誰でも付けられるので読まない。
//!
//! 読むのは断ったログインの履歴の写し（`SignInFailureRecordingSink`）だけで、[`RequestCountry`] として渡す。

use crate::domain::sign_in_history::RequestCountry;
use crate::domain::user_device::CountryCode;
use assay_contracts::auth::CLIENT_COUNTRY_HEADER;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

tokio::task_local! {
    static CLIENT_COUNTRY: Option<CountryCode>;
}

/// 内部の要求の間だけ、web が添えた国を置く。
pub async fn capture_client_country(request: Request, next: Next) -> Response {
    let country = request
        .headers()
        .get(CLIENT_COUNTRY_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(CountryCode::parse);
    CLIENT_COUNTRY.scope(country, next.run(request)).await
}

/// 今の要求の国を引く口（要求の外・外からの要求では `None`）。
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
