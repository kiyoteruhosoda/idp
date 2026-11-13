//! Tenant resolution middleware (ADR-0009 §7).
//!
//! For requests under `/{tenant_id}/...`, resolves the path's `:tenant_id` (UUID) and injects the target
//! tenant as [`ResolvedTenant`] via `Extension`. Handlers and use cases take `TenantContext` from this
//! Extension and pass it to repository calls (the tenant isolation line of defence; §8).
//!
//! Resolution rules (§7):
//! - `:tenant_id` is not a UUID → 404 (same as an unknown tenant; second stage of path collision avoidance; §6).
//! - not in `tenants` / `DISABLED` → 404.
//! - `ACTIVE` → injects [`ResolvedTenant`] and delegates onward.
//!
//! id → tenant is a hot path, so resolution is done by [`TenantResolutionService`] with a TTL cache +
//! invalidation on update. root is resolved the same way as a UUID, with no special branch (§1).
//!
//! # Mounting on the router (MT9)
//!
//! The actual `/{tenant_id}/...` routing is introduced in MT9. There this middleware is attached to the
//! tenant routes as `route_layer(from_fn_with_state(state, resolve_tenant))`.
//! Until MT9, as a transitional mode applying `AppState::default_tenant` (root resolved at startup) to every request,
//! this middleware is not mounted on the router (`state.tenant_resolution` is wiring for MT9).

use crate::application::tenant_resolution::TenantResolutionService;
use crate::domain::tenant::{Tenant, TenantId};
use crate::domain::tenant_context::TenantContext;
use crate::presentation::error::ApiError;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use assay_contracts::auth::UNKNOWN_TENANT_ERROR_CODE;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::collections::HashMap;

/// The target tenant resolved by `TenantResolver` (injected as an `Extension`).
///
/// Once extracted, "the tenant exists and is `ACTIVE`" is guaranteed. Handlers get the `TenantContext`
/// to pass to use cases via [`Self::context`].
#[derive(Debug, Clone)]
pub struct ResolvedTenant(Tenant);

impl ResolvedTenant {
    pub fn new(tenant: Tenant) -> Self {
        Self(tenant)
    }

    pub fn tenant(&self) -> &Tenant {
        &self.0
    }

    pub fn id(&self) -> TenantId {
        self.0.id
    }

    /// The tenant boundary passed to use cases.
    pub fn context(&self) -> TenantContext {
        TenantContext::new(self.0.id)
    }
}

/// The tenant resolution middleware itself (used with `from_fn_with_state`). Attached with `route_layer`
/// to the tenant routes under `/{tenant_id}/...`. Nested routes can have several path parameters
/// (e.g. `{tenant_id}` and `{client_id}`), so `tenant_id` is extracted by name.
pub async fn resolve_tenant(
    State(state): State<AppState>,
    Path(params): Path<HashMap<String, String>>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let Some(raw_tenant_id) = params.get("tenant_id") else {
        // The route definition has no `{tenant_id}` segment (wiring mistake). Falls back to 500.
        tracing::error!("resolve_tenant mounted on a route without a {{tenant_id}} segment");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "tenant segment missing",
        );
    };
    let resolved = match resolve(&state.tenant_resolution, raw_tenant_id).await {
        Ok(resolved) => resolved,
        Err(rejection) => return rejection,
    };
    request.extensions_mut().insert(resolved);
    next.run(request).await
}

/// Core logic of path segment → [`ResolvedTenant`] (separated from the middleware so it can be tested).
///
/// Non-UUID, unknown and `DISABLED` all become 404 (internal reasons are not leaked; §6, §7).
/// Only repository failures become 503 (temporary failure).
async fn resolve(
    service: &TenantResolutionService,
    raw_tenant_id: &str,
) -> Result<ResolvedTenant, Response> {
    let tenant_id: TenantId = match uuid::Uuid::parse_str(raw_tenant_id) {
        Ok(id) => id.into(),
        Err(_) => return Err(not_found()),
    };
    match service.resolve(tenant_id).await {
        Ok(Some(tenant)) => Ok(ResolvedTenant::new(tenant)),
        Ok(None) => Err(not_found()),
        Err(e) => {
            tracing::error!(error = %e, "failed to resolve tenant");
            Err(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "tenant resolution failed",
            ))
        }
    }
}

/// Resolves the tenant of the internal API (`/internal/*`; no tenant prefix; ADR-0009 §8) from the
/// `tenant_id` web sends in the DTO. **Missing, invalid UUID, nonexistent and `DISABLED` are all rejected
/// with 400 (fail-closed)**.
///
/// It used to fall back to the default tenant (root) as a transitional measure, but that was removed (SEC4)
/// once web moved to tenant routes (MT13). Keeping the fallback would let a login screen of another tenant
/// authenticate against the root tenant whenever web dropped `tenant_id` (tenant confusion).
///
/// **Existence and `ACTIVE` are checked too.** Tenant routes (`/{tenant_id}/...`) are stopped with 404 for
/// `DISABLED` by the [`resolve_tenant`] middleware, but the internal API has no prefix and does not go
/// through it. Back when only the UUID format was checked, **users of a disabled tenant could sign in via
/// `/internal/authenticate*`** (web has no DB and leaves existence checks to api by design, so web had
/// no way to stop it either). Disabling a tenant stops that organization's use, and the internal API
/// must not be a loophole around it.
///
/// Resolution goes through [`TenantResolutionService`] (TTL cache + invalidation on update), so the
/// auth hot path does not hit the DB every time.
pub async fn require_internal_tenant(
    tenants: &TenantResolutionService,
    raw_tenant_id: Option<&str>,
) -> Result<TenantContext, Response> {
    let raw = match raw_tenant_id.filter(|s| !s.is_empty()) {
        Some(raw) => raw,
        None => {
            tracing::warn!("missing tenant_id in internal request");
            return Err(invalid_tenant());
        }
    };
    let Ok(id) = uuid::Uuid::parse_str(raw) else {
        tracing::warn!(tenant_id = raw, "invalid tenant_id in internal request");
        return Err(invalid_tenant());
    };
    match tenants.resolve(id.into()).await {
        Ok(Some(tenant)) => Ok(TenantContext::new(tenant.id)),
        Ok(None) => {
            // Nonexistent and `DISABLED` are not distinguished (the only internal API caller is web and
            // distinguishing enables nothing more; not distinguishing also hides whether the tenant exists).
            tracing::warn!(
                tenant_id = raw,
                "internal request for an unknown or disabled tenant"
            );
            Err(unavailable_tenant())
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to resolve tenant for internal request");
            Err(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "tenant resolution failed",
            ))
        }
    }
}

/// An internal request naming a nonexistent or `DISABLED` tenant — the tenant could not be resolved.
///
/// **Carries a code distinguishable from other 400s** ([`UNKNOWN_TENANT_ERROR_CODE`] in `contracts`).
/// web maps it to the 404 screen and other non-2xx to 502 as "web implementation / configuration error"
/// (MT28). Telling them apart by the description would break silently the moment the wording changes.
fn unavailable_tenant() -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        UNKNOWN_TENANT_ERROR_CODE,
        "unknown or disabled tenant",
    )
}

fn invalid_tenant() -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "missing or invalid tenant_id",
    )
}

fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "not_found", "unknown tenant")
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({ "error": code, "message": message }))).into_response()
}

/// Requires the requested tenant to be root (ADR-0051; kept in ADR-0058 §8).
///
/// Used by endpoints handling resources shared by all tenants (the global SMTP route, signing keys).
///
/// ⚠ **This is the only guard for these endpoints.** Since ADR-0058 §8, `idp.smtp:*` can be granted in any
/// tenant (the tenant's own route is `/admin/settings/smtp`). So the permission check alone would let an
/// `idp.smtp:write` granted inside a tenant reach **the global route**. As long as `system_settings` is a
/// cross-tenant table, the caller imposes root.
pub fn require_root_tenant(tenant: &ResolvedTenant, locale: ApiLocale) -> Result<(), ApiError> {
    if tenant.tenant().is_root() {
        return Ok(());
    }
    Err(ApiError::Forbidden(
        ApiMessages::new(locale).get("api-permission-insufficient"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::tenant_resolution::TenantResolutionService;
    use crate::domain::cache::Cache;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::repositories::TenantRepository;
    use crate::domain::tenant::Tenant;
    use crate::domain::values::TenantStatus;
    use async_trait::async_trait;
    use axum::body::to_bytes;
    use chrono::{TimeZone, Utc};
    use std::sync::{Arc, Mutex};

    /// An always-empty cache for tests (reading the DB directly is enough for resolution path tests).
    struct NoopCache;
    impl Cache<TenantId, Tenant> for NoopCache {
        fn get(&self, _key: &TenantId) -> Option<Tenant> {
            None
        }
        fn insert(&self, _key: TenantId, _value: Tenant) {}
        fn invalidate(&self, _key: &TenantId) {}
    }

    struct FakeTenants(Mutex<Option<Tenant>>);
    #[async_trait]
    impl TenantRepository for FakeTenants {
        async fn create(&self, _t: &Tenant) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, id: TenantId) -> DomainResult<Option<Tenant>> {
            Ok(self.0.lock().unwrap().clone().filter(|t| t.id == id))
        }
        async fn find_root(&self) -> DomainResult<Option<Tenant>> {
            unreachable!()
        }
        async fn list_children(&self, _p: TenantId) -> DomainResult<Vec<Tenant>> {
            unreachable!()
        }
        async fn update(&self, _t: &Tenant) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _id: TenantId) -> DomainResult<()> {
            unreachable!()
        }
    }

    fn tenant(id: TenantId, status: TenantStatus) -> Tenant {
        let t = Utc.with_ymd_and_hms(2026, 7, 10, 0, 0, 0).unwrap();
        Tenant {
            id,
            parent_tenant_id: None,
            name: "root".to_string(),
            status,
            self_registration_enabled: false,
            email_login_enabled: false,
            created_at: t,
            updated_at: t,
        }
    }

    fn service(row: Option<Tenant>) -> TenantResolutionService {
        TenantResolutionService::new(Arc::new(FakeTenants(Mutex::new(row))), Arc::new(NoopCache))
    }

    #[tokio::test]
    async fn rejects_non_uuid_with_404() {
        let svc = service(None);
        let err = resolve(&svc, "not-a-uuid").await.expect_err("rejected");
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn rejects_unknown_tenant_with_404() {
        let svc = service(None);
        let err = resolve(&svc, &uuid::Uuid::now_v7().to_string())
            .await
            .expect_err("rejected");
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn rejects_disabled_tenant_with_404() {
        let id: TenantId = uuid::Uuid::now_v7().into();
        let svc = service(Some(tenant(id, TenantStatus::Disabled)));
        let err = resolve(&svc, &id.to_string()).await.expect_err("rejected");
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn resolves_active_tenant() {
        let id: TenantId = uuid::Uuid::now_v7().into();
        let svc = service(Some(tenant(id, TenantStatus::Active)));
        let resolved = resolve(&svc, &id.to_string()).await.expect("resolved");
        assert_eq!(resolved.id(), id);
        assert_eq!(resolved.context().tenant_id(), id);
    }

    #[tokio::test]
    async fn not_found_body_does_not_leak_internal_reason() {
        // Invalid UUID, unknown and DISABLED get the same 404 body (indistinguishable).
        let body = to_bytes(not_found().into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "not_found");
    }
}
