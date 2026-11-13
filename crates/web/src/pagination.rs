//! Building the list screens' pager (prev/next links) (G7).
//!
//! Paging itself is done by the api (DB); web only carries over "where we are" in the query string
//! and draws prev/next links. The rules (whether a next page exists, overflow protection) are not
//! duplicated per list but collected in this module.

/// The pager's prev/next links. `None` when not applicable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PagerLinks {
    pub prev: Option<String>,
    pub next: Option<String>,
}

/// Builds the prev/next links.
///
/// - `base`: destination without the query string (e.g. `/{tenant}/admin/clients`)
/// - `extra`: queries to carry over besides `offset` (filter terms etc.; values are encoded here)
/// - `offset` / `limit`: the position and step **actually applied by the api**
/// - `total`: total count after filtering
///
/// Whether a next page exists is decided by the **total count**. Deciding by whether the received count is below
/// `limit` would show a link to an empty page when the last page is exactly full.
pub fn pager_links(
    base: &str,
    extra: &[(&str, &str)],
    offset: i64,
    limit: i64,
    total: i64,
) -> PagerLinks {
    // limit is the value applied by the api. It never returns 0 or less, but reject it to be safe for the addition.
    let limit = limit.max(1);
    let offset = offset.max(0);
    // `offset` comes from the query (`?offset=9223372036854775807` happens too). Plain addition would
    // panic on overflow in debug builds and wrap to a negative value in release builds, producing a bogus
    // "next" link, so use saturating addition. A saturated value is never below `total`, so no "next" (as intended).
    let next_offset = offset.saturating_add(limit);
    PagerLinks {
        prev: (offset > 0).then(|| href(base, extra, (offset - limit).max(0))),
        next: (next_offset < total).then(|| href(base, extra, next_offset)),
    }
}

fn href(base: &str, extra: &[(&str, &str)], offset: i64) -> String {
    let mut query = format!("offset={offset}");
    for (key, value) in extra {
        if value.is_empty() {
            continue;
        }
        query.push_str(&format!("&{}={}", urlencode(key), urlencode(value)));
    }
    format!("{base}?{query}")
}

/// Percent-encodes a value for the query string (converts everything except RFC 3986 unreserved).
pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Paging query passed to the api. `offset` is always included; `limit` is omitted when the default suffices
/// (deciding limits and defaults is the api's job; web does not duplicate it).
pub fn page_query(offset: i64) -> Vec<(&'static str, String)> {
    vec![("offset", offset.max(0).to_string())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_page_has_no_previous_link() {
        let links = pager_links("/t/admin/clients", &[], 0, 50, 120);
        assert_eq!(links.prev, None);
        assert_eq!(links.next.as_deref(), Some("/t/admin/clients?offset=50"));
    }

    /// Even if the last page is exactly `limit` items, no "next" is shown (decided by total count).
    #[test]
    fn a_full_last_page_does_not_offer_a_next_link() {
        let links = pager_links("/t/admin/clients", &[], 50, 50, 100);
        assert_eq!(links.prev.as_deref(), Some("/t/admin/clients?offset=0"));
        assert_eq!(links.next, None);
    }

    /// `offset` is user input. Saturating addition causes neither panic nor wrap-around.
    #[test]
    fn a_saturating_offset_never_produces_a_next_link() {
        let links = pager_links("/t/admin/clients", &[], i64::MAX, 50, 100);
        assert_eq!(links.next, None);
        assert!(links.prev.is_some());
    }

    #[test]
    fn extra_query_values_are_percent_encoded_and_empty_ones_dropped() {
        let links = pager_links(
            "/t/admin/members",
            &[("q", "a b&c"), ("sort", "")],
            0,
            10,
            30,
        );
        assert_eq!(
            links.next.as_deref(),
            Some("/t/admin/members?offset=10&q=a%20b%26c")
        );
    }
}
