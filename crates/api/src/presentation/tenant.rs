//! テナント解決 middleware（ADR-0009 §7）。
//!
//! `/{tenant_id}/...` 配下のリクエストで、パスの `:tenant_id`（UUID）を解決し、処理対象のテナントを
//! [`ResolvedTenant`] として `Extension` 注入する。ハンドラ・ユースケースはこの Extension から
//! `TenantContext` を取り出してリポジトリ呼び出しに渡す（テナント分離の防御線。§8）。
//!
//! 解決規則（§7）:
//! - `:tenant_id` が UUID 形式でない → 404（未知のテナントと同じ扱い。パス衝突回避の第 2 段。§6）。
//! - `tenants` に存在しない / `DISABLED` → 404。
//! - `ACTIVE` → [`ResolvedTenant`] を注入して後続へ委譲する。
//!
//! id → tenant はホットパスのため、解決は TTL キャッシュ + 更新時 invalidation 付きの
//! [`TenantResolutionService`] が担う。root も同一経路で UUID として解決し、特別分岐は設けない（§1）。
//!
//! # ルーターへの mount（MT9）
//!
//! 実際の `/{tenant_id}/...` ルーティングは MT9 で導入する。本 middleware はそこで
//! `route_layer(from_fn_with_state(state, resolve_tenant))` として テナントルート群へ付与する。
//! MT9 までは `AppState::default_tenant`（起動時に解決した root）を全リクエストへ適用する過渡運用のため、
//! 本 middleware はルーターへ mount されない（`state.tenant_resolution` は MT9 のための配線）。

use crate::application::tenant_resolution::TenantResolutionService;
use crate::domain::tenant::{Tenant, TenantId};
use crate::domain::tenant_context::TenantContext;
use crate::presentation::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::collections::HashMap;

/// `TenantResolver` が解決した処理対象テナント（`Extension` として注入される）。
///
/// 抽出できた時点で「テナントが実在し `ACTIVE`」が保証される。ハンドラは [`Self::context`] で
/// ユースケースへ渡す `TenantContext` を得る。
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

    /// ユースケースへ渡すテナント境界。
    pub fn context(&self) -> TenantContext {
        TenantContext::new(self.0.id)
    }
}

/// テナント解決 middleware 本体（`from_fn_with_state` で使う）。`/{tenant_id}/...` 配下の
/// テナントルート群へ `route_layer` で付与する。ネストしたルートは複数のパスパラメータ
/// （例: `{tenant_id}` と `{client_id}`）を持ちうるため、`tenant_id` を名前で取り出す。
pub async fn resolve_tenant(
    State(state): State<AppState>,
    Path(params): Path<HashMap<String, String>>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let Some(raw_tenant_id) = params.get("tenant_id") else {
        // ルート定義に `{tenant_id}` セグメントが無い（配線ミス）。500 に倒す。
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

/// パス片 → [`ResolvedTenant`] の中核ロジック（middleware 本体から分離してテスト可能にする）。
///
/// UUID 形式でない・未知・`DISABLED` はいずれも 404 に倒す（内部理由は漏らさない。§6・§7）。
/// リポジトリ障害のみ 503（一時障害）に倒す。
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

/// 内部 API（`/internal/*`。テナントプレフィクス無し。ADR-0009 §8）のテナントを、web が DTO で送る
/// `tenant_id` から解決する。**未指定・UUID 不正は 400 で拒否する（fail-closed）**。
///
/// かつては過渡措置として既定テナント（root）へフォールバックしていたが、web のテナント経路化
/// （MT13）完了に伴い撤去した（SEC4）。フォールバックを残すと、web が `tenant_id` を落とした場合に
/// 別テナントのログイン画面から root テナントに対する認証が成立してしまう（テナント混同）。
pub fn require_internal_tenant(raw_tenant_id: Option<&str>) -> Result<TenantContext, Response> {
    match raw_tenant_id.filter(|s| !s.is_empty()) {
        Some(raw) => match uuid::Uuid::parse_str(raw) {
            Ok(id) => Ok(TenantContext::new(id.into())),
            Err(_) => {
                tracing::warn!(tenant_id = raw, "invalid tenant_id in internal request");
                Err(invalid_tenant())
            }
        },
        None => {
            tracing::warn!("missing tenant_id in internal request");
            Err(invalid_tenant())
        }
    }
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

    /// テスト用の常に空なキャッシュ（解決経路のテストでは DB 直読で十分）。
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
            created_at: t,
            updated_at: t,
        }
    }

    fn service(row: Option<Tenant>) -> TenantResolutionService {
        TenantResolutionService::new(
            Arc::new(FakeTenants(Mutex::new(row))),
            Arc::new(NoopCache),
        )
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
        // UUID 不正・未知・DISABLED は同一の 404 本文にする（識別不能）。
        let body = to_bytes(not_found().into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "not_found");
    }
}
