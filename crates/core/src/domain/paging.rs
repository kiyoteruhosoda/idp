//! Shared vocabulary for split retrieval of lists (paging; G7).
//!
//! Admin API lists return **one page plus the total count** so responses don't grow with tenant
//! size. Only two things are defined here: "from which item, how many" ([`PageRequest`]) and "one
//! page + total" ([`Page`]). Filter conditions are specific to each list, so each domain type holds
//! them (e.g. [`crate::domain::tenant_membership::TenantMemberFilter`]).
//!
//! Clamping (defaults, upper bound) lives in this type rather than the Application layer. The
//! Presentation layer need not know the limits, and the same rule is not duplicated across lists.

/// Range to fetch. Guarantees at construction that `limit` >= 1 and `offset` >= 0
/// ([`PageRequest::clamped`] is the only entry point so the fields cannot be built directly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRequest {
    limit: i64,
    offset: i64,
}

impl PageRequest {
    /// Brings unvalidated requested values (from the query string) into the allowed range.
    ///
    /// - `limit`: unset or <= 0 becomes `default`; above `max` becomes `max`
    /// - `offset`: unset or negative becomes 0
    pub fn clamped(limit: Option<i64>, offset: Option<i64>, default: i64, max: i64) -> Self {
        let limit = match limit {
            Some(l) if l > 0 => l.min(max),
            _ => default,
        };
        Self {
            limit,
            offset: offset.unwrap_or(0).max(0),
        }
    }

    /// Number of items actually fetched (>= 1).
    pub fn limit(&self) -> i64 {
        self.limit
    }

    /// Number of items actually skipped (>= 0).
    pub fn offset(&self) -> i64 {
        self.offset
    }
}

/// One page of items and the total count under the same filter.
///
/// The total is returned because callers **cannot tell whether a next page exists from the received
/// count** (if the last page is exactly `limit` items, a link to an empty page would appear).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub total: i64,
}

impl<T> Page<T> {
    pub fn new(items: Vec<T>, total: i64) -> Self {
        Self { items, total }
    }

    /// Cuts one page out of a `Vec` holding all items. A helper for implementations that cannot
    /// write `LIMIT`/`OFFSET` in the DB (in-memory test fakes); the production sqlx implementation
    /// does not use it.
    pub fn from_all(all: Vec<T>, request: PageRequest) -> Self {
        let total = all.len() as i64;
        let items = all
            .into_iter()
            .skip(request.offset().max(0) as usize)
            .take(request.limit().max(0) as usize)
            .collect();
        Self { items, total }
    }
}

/// One page of results together with the range **actually applied**.
///
/// Callers (Presentation, web's pager) use this instead of the requested values. The clamping rule
/// is not duplicated in upper layers, and paging does not break when "`limit=10000` was requested
/// but 200 was applied".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagedResult<T> {
    pub page: Page<T>,
    pub applied: PageRequest,
}

impl<T> PagedResult<T> {
    pub fn new(page: Page<T>, applied: PageRequest) -> Self {
        Self { page, applied }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_limit_to_the_allowed_range() {
        assert_eq!(PageRequest::clamped(None, None, 50, 200).limit(), 50);
        assert_eq!(PageRequest::clamped(Some(0), None, 50, 200).limit(), 50);
        assert_eq!(PageRequest::clamped(Some(-1), None, 50, 200).limit(), 50);
        assert_eq!(PageRequest::clamped(Some(10), None, 50, 200).limit(), 10);
        assert_eq!(
            PageRequest::clamped(Some(10_000), None, 50, 200).limit(),
            200
        );
    }

    #[test]
    fn negative_offset_is_treated_as_the_first_page() {
        assert_eq!(PageRequest::clamped(None, Some(-5), 50, 200).offset(), 0);
        assert_eq!(PageRequest::clamped(None, Some(7), 50, 200).offset(), 7);
    }

    #[test]
    fn slicing_all_items_keeps_the_unfiltered_total() {
        let page = Page::from_all(
            vec![1, 2, 3, 4, 5],
            PageRequest::clamped(Some(2), Some(1), 50, 200),
        );
        assert_eq!(page.items, vec![2, 3]);
        assert_eq!(page.total, 5);
    }

    /// An out-of-range `offset` yields an empty page, but the total is unchanged (the screen can
    /// show "Previous").
    #[test]
    fn offset_past_the_end_yields_an_empty_page() {
        let page = Page::from_all(
            vec![1, 2, 3],
            PageRequest::clamped(Some(2), Some(99), 50, 200),
        );
        assert!(page.items.is_empty());
        assert_eq!(page.total, 3);
    }
}
