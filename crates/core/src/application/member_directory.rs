//! メンバー一覧の参照ユースケース（`GET /{tenant_id}/admin/members`。MT22）。
//!
//! 当該テナントに参加している利用者（HOME / GUEST）を、メール・氏名の部分一致で絞り込みながら
//! ページ単位で返す。参照専用のため監査記録は行わない（読み取りは `log` テーブル側で追える）。
//!
//! メンバーシップの**変更**（招待・承諾・解除・一時停止）は [`crate::application::invitation`] の
//! 責務で、本サービスは参照のみを担う（SRP。[`crate::application::audit_query`] と同じ位置づけ）。

use crate::domain::error::DomainError;
use crate::domain::repositories::TenantMemberQuery;
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_membership::{TenantMemberFilter, TenantMemberPage};
use std::sync::Arc;

/// 1 ページの既定件数。
pub const DEFAULT_LIMIT: i64 = 50;
/// 1 ページの上限件数（過大な取得を防ぐ）。
pub const MAX_LIMIT: i64 = 200;

/// 検索パラメータ（Presentation から受け取る素の値。`limit`/`offset` は未クランプ）。
#[derive(Debug, Clone, Default)]
pub struct MemberSearchParams {
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// 検索結果。`limit` / `offset` は**実際に適用した**値（クランプ後）で、呼び出し側がページ送りを
/// 計算するときに要求値ではなくこちらを使えるようにする（クランプ規則を Presentation 層へ
/// 複製しないため）。
#[derive(Debug)]
pub struct MemberSearchResult {
    pub page: TenantMemberPage,
    pub limit: i64,
    pub offset: i64,
}

pub struct MemberDirectoryService {
    members: Arc<dyn TenantMemberQuery>,
}

impl MemberDirectoryService {
    pub fn new(members: Arc<dyn TenantMemberQuery>) -> Self {
        Self { members }
    }

    /// 条件に一致するメンバーを 1 ページ分返す。テナントは要求テナントに固定する
    /// （テナント越しの閲覧を防ぐため、呼び出し側が上書きできる余地を作らない）。
    pub async fn search(
        &self,
        tenant: TenantContext,
        params: MemberSearchParams,
    ) -> Result<MemberSearchResult, DomainError> {
        let filter = TenantMemberFilter {
            tenant_id: tenant.tenant_id(),
            search: normalize(params.search),
            limit: clamp_limit(params.limit),
            offset: params.offset.unwrap_or(0).max(0),
        };
        let page = self.members.search(&filter).await?;
        Ok(MemberSearchResult {
            page,
            limit: filter.limit,
            offset: filter.offset,
        })
    }
}

/// `limit` を 1..=MAX_LIMIT に収める。未指定・非正値は既定値。
fn clamp_limit(limit: Option<i64>) -> i64 {
    match limit {
        Some(l) if l > 0 => l.min(MAX_LIMIT),
        _ => DEFAULT_LIMIT,
    }
}

/// 空文字列を `None` に正規化する（クエリ未指定の `?q=` を「絞り込みなし」として扱うため）。
fn normalize(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::tenant::TenantId;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use uuid::Uuid;

    /// 渡されたフィルタを記録するだけのフェイク（クランプ・正規化の検証用）。
    #[derive(Default)]
    struct CapturingQuery {
        seen: Mutex<Vec<TenantMemberFilter>>,
    }
    #[async_trait]
    impl TenantMemberQuery for CapturingQuery {
        async fn search(&self, filter: &TenantMemberFilter) -> DomainResult<TenantMemberPage> {
            self.seen.lock().unwrap().push(filter.clone());
            Ok(TenantMemberPage {
                members: Vec::new(),
                total: 0,
            })
        }
    }

    fn tenant() -> TenantContext {
        TenantContext::new(TenantId::from(Uuid::from_u128(
            0x0197_0000_0000_7000_8000_0000_0000_0001,
        )))
    }

    async fn captured(params: MemberSearchParams) -> TenantMemberFilter {
        let query = Arc::new(CapturingQuery::default());
        let svc = MemberDirectoryService::new(query.clone());
        svc.search(tenant(), params).await.expect("search ok");
        let seen = query.seen.lock().unwrap();
        seen.first().expect("filter captured").clone()
    }

    #[test]
    fn clamps_limit_to_bounds_and_defaults() {
        assert_eq!(clamp_limit(None), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(0)), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(-5)), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(10)), 10);
        assert_eq!(clamp_limit(Some(MAX_LIMIT + 100)), MAX_LIMIT);
    }

    #[tokio::test]
    async fn blank_search_means_no_filter_and_negative_offset_is_clamped() {
        let filter = captured(MemberSearchParams {
            search: Some("   ".to_string()),
            limit: None,
            offset: Some(-10),
        })
        .await;
        assert_eq!(filter.search, None);
        assert_eq!(filter.offset, 0);
        assert_eq!(filter.limit, DEFAULT_LIMIT);
    }

    #[tokio::test]
    async fn search_term_is_trimmed_and_tenant_is_fixed_to_the_request_tenant() {
        let filter = captured(MemberSearchParams {
            search: Some("  Alice  ".to_string()),
            limit: Some(5),
            offset: Some(100),
        })
        .await;
        assert_eq!(filter.search.as_deref(), Some("Alice"));
        assert_eq!(filter.limit, 5);
        assert_eq!(filter.offset, 100);
        assert_eq!(filter.tenant_id, tenant().tenant_id());
    }
}
