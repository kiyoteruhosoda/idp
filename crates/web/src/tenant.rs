//! Extracts tenant_id from tenant routes (`/{tenant_id}/...`) (ADR-0009 §6, §8, MT13).
//!
//! web has no DB, so existence is not checked (only the UUID format is validated; existence and `ACTIVE` checks are
//! left to 404/403 from the api calls; the api's `TenantResolver` is the last line of defense).

use axum::extract::{Path, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;

tokio::task_local! {
    /// The tenant-relative path of the request being processed (e.g. `/admin/accounts`).
    static TENANT_RELATIVE_PATH: String;
}

/// The tenant-relative path of the request being processed (without `/{tenant_id}`).
///
/// Read by the admin console's shared layout to mark the open screen in the menu and tab title
/// (`templates::current_console_nav_item`). It is not carried via each screen's template struct or
/// `resolve_admin` arguments because the value is a **request attribute**, not per-screen
/// input -- if any one of 100+ call sites forgot to pass it, that screen alone would
/// lack the marker. `None` for renders that do not go through [`capture_tenant`] (e.g. template unit tests).
pub fn current_relative_path() -> Option<String> {
    TENANT_RELATIVE_PATH.try_with(|path| path.clone()).ok()
}

/// Renders as if the given path were open (for template tests).
#[cfg(test)]
pub(crate) fn with_relative_path<R>(path: &str, render: impl FnOnce() -> R) -> R {
    TENANT_RELATIVE_PATH.sync_scope(path.to_string(), render)
}

/// tenant_id resolved from the route (injected as an `Extension`).
#[derive(Debug, Clone)]
pub struct WebTenant(pub String);

impl WebTenant {
    /// `/{tenant_id}` prefix for building paths.
    pub fn prefix(&self) -> String {
        format!("/{}", self.0)
    }
}

/// The tenant route middleware itself. Nested routes may have several path parameters, so
/// `tenant_id` is extracted by name (same approach as the api's `resolve_tenant`).
pub async fn capture_tenant(
    Path(params): Path<HashMap<String, String>>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(tenant_id) = params.get("tenant_id") else {
        tracing::error!("capture_tenant mounted on a route without a {{tenant_id}} segment");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if uuid::Uuid::parse_str(tenant_id).is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = relative_path(request.uri().path(), tenant_id);
    request
        .extensions_mut()
        .insert(WebTenant(tenant_id.clone()));
    TENANT_RELATIVE_PATH.scope(path, next.run(request)).await
}

/// Removes `/{tenant_id}` from the request path.
///
/// Inside `nest("/{tenant_id}", …)` axum has already stripped it, so it is returned as is. Strip it if present
/// so the value is the same even if moved outside.
fn relative_path(path: &str, tenant_id: &str) -> String {
    let prefix = format!("/{tenant_id}");
    match path.strip_prefix(prefix.as_str()) {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => rest.to_string(),
        _ => path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_relative_path_never_carries_the_tenant_prefix() {
        let tenant = "00000000-0000-7000-8000-000000000001";
        assert_eq!(relative_path("/admin/accounts", tenant), "/admin/accounts");
        assert_eq!(
            relative_path(&format!("/{tenant}/admin/accounts"), tenant),
            "/admin/accounts"
        );
        assert!(relative_path(&format!("/{tenant}"), tenant).is_empty());
        // Do not cut other paths that merely share the prefix.
        assert_eq!(
            relative_path(&format!("/{tenant}0/admin"), tenant),
            format!("/{tenant}0/admin")
        );
    }

    #[test]
    fn the_relative_path_is_absent_outside_a_request() {
        assert_eq!(current_relative_path(), None);
        assert_eq!(
            with_relative_path("/admin", current_relative_path),
            Some("/admin".to_string())
        );
    }
}
