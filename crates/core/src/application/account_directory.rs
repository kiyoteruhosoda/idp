//! アカウント一覧の参照ユースケース（`GET /{tenant_id}/admin/accounts`。ADR-0065）。
//!
//! 人とサービスアカウントを 1 つの一覧に並べる。参照専用のため監査記録は行わない
//! （[`crate::application::member_directory`] と同じ位置づけ）。
//!
//! # 読める種別だけを並べる
//!
//! 人を読む権限（`idp.members:read`）とサービスアカウントを読む権限（`idp.clients:read`）は別である。
//! 一覧は**呼んだ主体が読める種別だけ**を並べる。新しい権限コード（「アカウントを読む」）は作らない
//! ——作ると既存の 2 つとの含意をもう 1 本決め直すことになる（ADR-0065 の捨てた案 D）。
//!
//! - 種別を指定しない: 読める種別をすべて並べる。1 つも読めなければ [`AccountDirectoryError::Forbidden`]
//! - 種別を指定する: その種別を読めなければ `Forbidden`。⚠ **黙って空にしない** ——空の一覧は
//!   「居ない」と読まれる

use crate::application::member_directory::{DEFAULT_LIMIT, MAX_LIMIT};
use crate::domain::account::{AccountFilter, AccountKind, AccountPage, ServiceAccount};
use crate::domain::permission;
use crate::domain::repositories::AccountQuery;
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum AccountDirectoryError {
    /// 求められた種別（または、どの種別も）を読む権限が無い。
    Forbidden,
    Internal(String),
}

/// 検索パラメータ（Presentation から受け取る素の値。`limit`/`offset` は未クランプ）。
#[derive(Debug, Clone, Default)]
pub struct AccountSearchParams {
    /// 並べる種別。`None` は「読めるものすべて」。
    pub kind: Option<AccountKind>,
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// 検索結果。`limit` / `offset` は実際に適用した値、`kinds` は実際に並べた種別。
#[derive(Debug)]
pub struct AccountSearchResult {
    pub page: AccountPage,
    pub kinds: Vec<AccountKind>,
    /// この主体が読める種別（画面が絞り込みの選択肢を出すため。`kinds` とは別 ——種別を
    /// 指定したときも、ほかに何を選べるかは要る）。
    pub readable: Vec<AccountKind>,
    pub limit: i64,
    pub offset: i64,
}

/// 種別を読むのに要る権限コード。
fn read_permission(kind: AccountKind) -> &'static str {
    match kind {
        AccountKind::User => permission::MEMBERS_READ,
        AccountKind::ServiceAccount => permission::CLIENTS_READ,
    }
}

/// 保有権限から、読める種別を返す（並びは [`AccountKind::ALL`] の順）。
pub fn readable_kinds<S: AsRef<str>>(held: &[S]) -> Vec<AccountKind> {
    AccountKind::ALL
        .into_iter()
        .filter(|kind| permission::satisfies(held, read_permission(*kind)))
        .collect()
}

pub struct AccountDirectoryService {
    accounts: Arc<dyn AccountQuery>,
}

impl AccountDirectoryService {
    pub fn new(accounts: Arc<dyn AccountQuery>) -> Self {
        Self { accounts }
    }

    /// 条件に一致するアカウントを 1 ページ分返す。テナントは要求テナントに固定する。
    ///
    /// `held` は呼んだ主体の保有権限コード（管理トークンの `perms`。含意は未展開）。
    pub async fn search<S: AsRef<str>>(
        &self,
        tenant: TenantContext,
        held: &[S],
        params: AccountSearchParams,
    ) -> Result<AccountSearchResult, AccountDirectoryError> {
        let readable = readable_kinds(held);
        let kinds = match params.kind {
            Some(kind) if readable.contains(&kind) => vec![kind],
            Some(_) => return Err(AccountDirectoryError::Forbidden),
            None if readable.is_empty() => return Err(AccountDirectoryError::Forbidden),
            None => readable.clone(),
        };
        let filter = AccountFilter {
            tenant_id: tenant.tenant_id(),
            kinds: kinds.clone(),
            search: params
                .search
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            limit: match params.limit {
                Some(l) if l > 0 => l.min(MAX_LIMIT),
                _ => DEFAULT_LIMIT,
            },
            offset: params.offset.unwrap_or(0).max(0),
        };
        let page = self
            .accounts
            .search(&filter)
            .await
            .map_err(|e| AccountDirectoryError::Internal(e.to_string()))?;
        Ok(AccountSearchResult {
            page,
            kinds,
            readable,
            limit: filter.limit,
            offset: filter.offset,
        })
    }

    /// サービスアカウント 1 件を `client_id` で引く（1 件の画面）。要求テナントのサービスアカウントで
    /// なければ `None`（連携先・削除済み・他テナントを区別しない）。
    pub async fn find_service_account(
        &self,
        tenant: TenantContext,
        client_id: &str,
    ) -> Result<Option<ServiceAccount>, AccountDirectoryError> {
        self.accounts
            .find_service_account(tenant.tenant_id(), client_id.trim())
            .await
            .map_err(|e| AccountDirectoryError::Internal(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::tenant::TenantId;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use uuid::Uuid;

    #[derive(Default)]
    struct CapturingQuery {
        seen: Mutex<Vec<AccountFilter>>,
    }
    #[async_trait]
    impl AccountQuery for CapturingQuery {
        async fn search(&self, filter: &AccountFilter) -> DomainResult<AccountPage> {
            self.seen.lock().unwrap().push(filter.clone());
            Ok(AccountPage {
                accounts: Vec::new(),
                total: 0,
            })
        }
        async fn find_service_account(
            &self,
            _t: TenantId,
            _c: &str,
        ) -> DomainResult<Option<ServiceAccount>> {
            Ok(None)
        }
    }

    fn tenant() -> TenantContext {
        TenantContext::new(TenantId::from(Uuid::from_u128(
            0x0197_0000_0000_7000_8000_0000_0000_0001,
        )))
    }

    async fn run(
        held: &[&str],
        kind: Option<AccountKind>,
    ) -> (
        Result<AccountSearchResult, AccountDirectoryError>,
        Vec<AccountFilter>,
    ) {
        let query = Arc::new(CapturingQuery::default());
        let svc = AccountDirectoryService::new(query.clone());
        let result = svc
            .search(
                tenant(),
                held,
                AccountSearchParams {
                    kind,
                    search: Some("  wiki ".to_string()),
                    limit: Some(10_000),
                    offset: Some(-1),
                },
            )
            .await;
        let seen = query.seen.lock().unwrap().clone();
        (result, seen)
    }

    #[test]
    fn readable_kinds_follow_the_implication_rules() {
        assert_eq!(
            readable_kinds(&[permission::TENANT_ADMIN]),
            vec![AccountKind::User, AccountKind::ServiceAccount]
        );
        assert_eq!(
            readable_kinds(&[permission::MEMBERS_WRITE]),
            vec![AccountKind::User]
        );
        assert_eq!(
            readable_kinds(&[permission::CLIENTS_READ]),
            vec![AccountKind::ServiceAccount]
        );
        assert!(readable_kinds(&[permission::USERS_READ]).is_empty());
    }

    #[tokio::test]
    async fn without_a_kind_only_readable_kinds_are_listed() {
        let (result, seen) = run(&[permission::MEMBERS_READ], None).await;
        let result = result.expect("ok");
        assert_eq!(result.kinds, vec![AccountKind::User]);
        assert_eq!(seen[0].kinds, vec![AccountKind::User]);
        assert_eq!(seen[0].search.as_deref(), Some("wiki"));
        assert_eq!(seen[0].limit, MAX_LIMIT);
        assert_eq!(seen[0].offset, 0);
    }

    #[tokio::test]
    async fn asking_for_an_unreadable_kind_is_forbidden_not_empty() {
        let (result, seen) = run(
            &[permission::MEMBERS_READ],
            Some(AccountKind::ServiceAccount),
        )
        .await;
        assert_eq!(result.unwrap_err(), AccountDirectoryError::Forbidden);
        assert!(seen.is_empty(), "読めない種別で DB を引かない");
    }

    #[tokio::test]
    async fn nothing_readable_is_forbidden() {
        let (result, _) = run(&[permission::AUDIT_READ], None).await;
        assert_eq!(result.unwrap_err(), AccountDirectoryError::Forbidden);
    }

    #[tokio::test]
    async fn a_named_kind_keeps_the_other_readable_kinds_for_the_filter() {
        let (result, _) = run(
            &[permission::TENANT_ADMIN],
            Some(AccountKind::ServiceAccount),
        )
        .await;
        let result = result.expect("ok");
        assert_eq!(result.kinds, vec![AccountKind::ServiceAccount]);
        assert_eq!(
            result.readable,
            vec![AccountKind::User, AccountKind::ServiceAccount]
        );
    }
}
