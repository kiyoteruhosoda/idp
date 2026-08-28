//! テナント作成・管理ユースケース（ADR-0009 §4・§5・§6）。
//!
//! テナント作成は「あるテナント配下への子テナント作成」として一律に扱う。`idp.system.admin`（scope =
//! root のみ存在）を要求するため、**実質的にテナントを作成できるのは root だけ**になる（§4。判定は
//! Presentation の `RequirePerms<IdpSystemAdmin>` が担う）。
//!
//! 作成時に、**作成者自身**を新テナントのブートストラップ管理者として登録する（ACTIVE な GUEST
//! メンバーシップ＋新テナント scope の `idp.tenant.admin`）。作成者は自身の SSO セッションのまま新
//! テナントの管理コンソールへ入り、正式な管理者（新テナント所属の HOME 利用者）を登録して
//! `idp.tenant.admin` を付与し、最後に自身のゲストメンバーシップを解除して離脱する（解除時に当該テナント
//! scope の権限行も後始末される。§3）。初期パスワードの受け渡しを伴わないため、平文パスワードは返さない。
//!
//! テナント行・作成者のブートストラップメンバーシップ・権限付与は
//! [`TenantProvisioningRepository`] が**単一トランザクション**で永続化する（unit of work。REF2）。
//! 途中失敗で「管理者のいないテナント」が残ることはない。
//!
//! テナントの取得・更新・削除は**当該テナントの直下の子**のみを対象とする（`parent_tenant_id` 照合。
//! 他テナントの子は不存在として扱う）。root テナントはアプリ層で削除を禁止する（§1）。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::message::MessageKey;
use crate::domain::paging::{PageRequest, PagedResult};
use crate::domain::repositories::{
    TenantDomainRepository, TenantProvisioningRepository, TenantRepository,
};
use crate::domain::tenant::{AccentColor, Tenant, TenantId};
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_domain::{validate_domain, TenantDomain};
use crate::domain::tenant_membership::TenantMembership;
use crate::domain::values::TenantStatus;
use std::sync::Arc;
use uuid::Uuid;

/// 作成者（ブートストラップ管理者）へ付与する権限（scope = 新テナント。ADR-0009 §4）。
const TENANT_ADMIN_PERMISSION: &str = "idp.tenant.admin";
/// 子テナント一覧 1 ページの既定件数（G7）。
pub const DEFAULT_PAGE_LIMIT: i64 = 50;
/// 子テナント一覧 1 ページの上限件数（過大な取得を防ぐ）。
pub const MAX_PAGE_LIMIT: i64 = 200;

#[derive(Debug, Clone)]
pub struct CreateTenantCommand {
    pub name: String,
}

/// 部分更新コマンド。`None` のフィールドは変更しない。
#[derive(Debug, Clone, Default)]
pub struct UpdateTenantCommand {
    pub name: Option<String>,
    pub status: Option<TenantStatus>,
}

#[derive(Debug, thiserror::Error)]
pub enum TenantManagementError {
    #[error("validation error: {0}")]
    Validation(MessageKey),
    #[error("not found")]
    NotFound,
    #[error("forbidden: {0}")]
    Forbidden(MessageKey),
    #[error("conflict: {0}")]
    Conflict(MessageKey),
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct TenantManagementService {
    tenants: Arc<dyn TenantRepository>,
    /// テナントへ割り当てたドメイン（ADR-0029）。ログインの解決と同じ表を管理側からも触る。
    tenant_domains: Arc<dyn TenantDomainRepository>,
    provisioning: Arc<dyn TenantProvisioningRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl TenantManagementService {
    pub fn new(
        tenants: Arc<dyn TenantRepository>,
        tenant_domains: Arc<dyn TenantDomainRepository>,
        provisioning: Arc<dyn TenantProvisioningRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            tenants,
            tenant_domains,
            provisioning,
            audit,
            clock,
            ids,
        }
    }

    /// `requesting` テナント配下に子テナントを作成し、**作成者自身**（`actor`）を新テナントの
    /// ブートストラップ管理者として登録する（ACTIVE な GUEST メンバーシップ＋新テナント scope の
    /// `idp.tenant.admin`）。3 行（テナント・メンバーシップ・権限）は単一トランザクションで永続化する
    /// （unit of work。REF2）。作成者は以後、正式な管理者を登録・付与してから自身を解除する（§3・§4）。
    pub async fn create_tenant(
        &self,
        requesting: TenantContext,
        cmd: CreateTenantCommand,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<Tenant, TenantManagementError> {
        let name = validate_name(cmd.name)?;

        // 作成者は新テナントのブートストラップ管理者になる（下記）。クライアント主体には
        // メンバーシップも `idp.tenant.admin` も持たせられないため、作成した瞬間に**誰も
        // 管理者が居ないテナント**ができてしまう。そうなる前に断る。
        // （`idp.system.admin` はクライアントへ付与できないので実際には到達しないが、
        //  「到達しないから書かない」にすると、将来この前提が変わったときに静かに壊れる。）
        let Some(bootstrap_admin) = actor.user_id() else {
            return Err(TenantManagementError::Forbidden(MessageKey::new(
                "api-tenant-create-requires-user-actor",
            )));
        };

        let now = self.clock.now();
        let tenant = Tenant {
            id: TenantId::from(self.ids.new_id()),
            parent_tenant_id: Some(requesting.tenant_id()),
            name,
            // 色は作成時には決めない（テナント管理者が設定画面で選ぶ）。
            accent_color: None,
            status: TenantStatus::Active,
            // 自己登録は既定で無効（fail-closed。SEC6。有効化はテナント管理者が設定画面から行う）。
            self_registration_enabled: false,
            created_at: now,
            updated_at: now,
        };

        // 作成者を新テナントのブートストラップ管理者にする（ACTIVE GUEST。所属元は親テナントのまま）。
        let membership = TenantMembership::new_active_guest(tenant.id, bootstrap_admin, now);

        // テナント・作成者メンバーシップ・idp.tenant.admin 付与を原子的に永続化する（§4）。
        // 権限付与はキャッシュ付きリポジトリを経由しないが、テナント ID は今生成したものであり、
        // 判定キャッシュに該当キーが載っていることはない（stale deny は起きない）。
        self.provisioning
            .provision(&tenant, &membership, TENANT_ADMIN_PERMISSION, now)
            .await
            .map_err(|e| match e {
                // テナントの一意キーは単一 root の番兵列のみ（表示名は一意でない）。到達は競合時のみ。
                DomainError::Conflict(_) => {
                    TenantManagementError::Conflict(MessageKey::new("api-tenant-create-conflict"))
                }
                other => TenantManagementError::Internal(other.to_string()),
            })?;

        // 監査には内部 ID のみ記録する。
        self.audit
            .record(
                AuditEventType::TenantCreated,
                AuditResult::Success,
                Some(tenant.id),
                actor.user_id(),
                actor.client_id(),
                Some(&format!(
                    "tenant={} bootstrap_admin={}",
                    tenant.id, bootstrap_admin
                )),
                ctx,
            )
            .await;

        Ok(tenant)
    }

    /// `requesting` テナントの直下の子テナントを一覧する（§6）。
    pub async fn list_children(
        &self,
        requesting: TenantContext,
    ) -> Result<Vec<Tenant>, TenantManagementError> {
        self.tenants
            .list_children(requesting.tenant_id())
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))
    }

    /// 直下の子テナントを 1 ページ分返す（G7）。`limit` / `offset` は未検証の要求値を受け取り、
    /// 許容範囲へ収めたうえで**適用値**を結果に添える。
    pub async fn list_children_page(
        &self,
        requesting: TenantContext,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<PagedResult<Tenant>, TenantManagementError> {
        let request = PageRequest::clamped(limit, offset, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);
        let page = self
            .tenants
            .list_children_page(requesting.tenant_id(), request)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?;
        Ok(PagedResult::new(page, request))
    }

    /// `requesting` テナントの直下の子テナント 1 件を取得する。他テナントの子・不存在は `NotFound`。
    pub async fn get_child(
        &self,
        requesting: TenantContext,
        child_id: TenantId,
    ) -> Result<Tenant, TenantManagementError> {
        self.load_child(requesting, child_id).await
    }

    /// 子テナントの表示名・状態を更新する（`parent_tenant_id` は変更しない。§1）。
    pub async fn update_tenant(
        &self,
        requesting: TenantContext,
        child_id: TenantId,
        cmd: UpdateTenantCommand,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<Tenant, TenantManagementError> {
        let mut tenant = self.load_child(requesting, child_id).await?;
        if let Some(name) = cmd.name {
            tenant.name = validate_name(name)?;
        }
        if let Some(status) = cmd.status {
            tenant.status = status;
        }
        self.tenants
            .update(&tenant)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?;

        self.audit
            .record(
                AuditEventType::TenantUpdated,
                AuditResult::Success,
                Some(tenant.id),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("tenant={}", tenant.id)),
                ctx,
            )
            .await;
        Ok(tenant)
    }

    /// 現在（要求）テナント自身を取得する（設定画面のテナント設定区画。MT14）。子テナント限定の
    /// `update_tenant` とは異なり、テナント管理者（`idp.tenant.admin`）が自テナントを参照するために使う。
    pub async fn get_current(
        &self,
        current: TenantContext,
    ) -> Result<Tenant, TenantManagementError> {
        self.tenants
            .find_by_id(current.tenant_id())
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?
            .ok_or(TenantManagementError::NotFound)
    }

    /// 現在（要求）テナント自身の設定を更新する（設定画面のテナント設定区画。MT14・SEC6）。
    /// 表示名と自己登録トグル（`self_registration_enabled`。`None` は現状維持）を対象とし、認可は
    /// Presentation の `RequirePerms<IdpAdmin>`（`idp.tenant.admin`）が担う。`parent_tenant_id`・
    /// `status` は変更しない。
    pub async fn update_current_settings(
        &self,
        current: TenantContext,
        name: String,
        accent_color: Option<String>,
        self_registration_enabled: Option<bool>,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<Tenant, TenantManagementError> {
        let mut tenant = self.get_current(current).await?;
        tenant.name = validate_name(name)?;
        // 未指定（`None`）は「触らない」、空文字は「色を外す」。この 2 つを同じにすると、
        // 色の欄を持たない画面からの更新が色を消してしまう。
        if let Some(raw) = accent_color {
            tenant.accent_color =
                AccentColor::parse(&raw).map_err(TenantManagementError::Validation)?;
        }
        if let Some(enabled) = self_registration_enabled {
            tenant.self_registration_enabled = enabled;
        }
        self.tenants
            .update(&tenant)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?;
        self.audit
            .record(
                AuditEventType::TenantUpdated,
                AuditResult::Success,
                Some(tenant.id),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("tenant={} (self settings)", tenant.id)),
                ctx,
            )
            .await;
        Ok(tenant)
    }

    /// 子テナントを削除する。root は削除不可（§1）。配下に子が居る場合は `Conflict`。当該テナント自身に
    /// ユーザー/クライアントが存在する場合は DB の `ON DELETE RESTRICT` により `Conflict`（§1）。
    pub async fn delete_tenant(
        &self,
        requesting: TenantContext,
        child_id: TenantId,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), TenantManagementError> {
        let tenant = self.load_child(requesting, child_id).await?;
        // root は構造的に誰の子でもない（load_child で既に弾かれる）が、明示的に禁止して二重防御とする。
        if tenant.is_root() {
            return Err(TenantManagementError::Forbidden(MessageKey::new(
                "api-tenant-root-cannot-delete",
            )));
        }
        // 配下に子テナントが存在しないこと（アプリ層の事前検証。§1）。
        let grandchildren = self
            .tenants
            .list_children(tenant.id)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?;
        if !grandchildren.is_empty() {
            return Err(TenantManagementError::Conflict(MessageKey::new(
                "api-tenant-has-children",
            )));
        }

        // ユーザー/クライアントの残存は DB の FK（ON DELETE RESTRICT）が Conflict に倒す（§1）。
        self.tenants.delete(tenant.id).await.map_err(|e| match e {
            // FK（ON DELETE RESTRICT）による拒否 = 配下に利用者・クライアントが残っている（§1）。
            DomainError::Conflict(_) => {
                TenantManagementError::Conflict(MessageKey::new("api-tenant-has-dependents"))
            }
            other => TenantManagementError::Internal(other.to_string()),
        })?;

        self.audit
            .record(
                AuditEventType::TenantDeleted,
                AuditResult::Success,
                Some(tenant.id),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("tenant={}", tenant.id)),
                ctx,
            )
            .await;
        Ok(())
    }

    /// `child_id` が `requesting` の直下の子テナントであることを確かめて取得する（他テナントの子・
    /// 不存在は `NotFound` に倒し、存在を漏らさない。§6）。
    async fn load_child(
        &self,
        requesting: TenantContext,
        child_id: TenantId,
    ) -> Result<Tenant, TenantManagementError> {
        match self
            .tenants
            .find_by_id(child_id)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?
        {
            Some(tenant) if tenant.parent_tenant_id == Some(requesting.tenant_id()) => Ok(tenant),
            _ => Err(TenantManagementError::NotFound),
        }
    }

    // ── ドメインの割り当て（ADR-0029）─────────────────────────────────────────

    /// ドメインの操作対象は**自テナントまたは直下の子**とする。
    ///
    /// 子だけに限らないのは、root 自身にもドメインが要るためである（root の利用者は作成した
    /// テナントへゲストとして入るので、ドメイン修飾で入れなければ意味がない）。root は誰の子でも
    /// ないので `load_child` では到達できない。
    async fn load_self_or_child(
        &self,
        requesting: TenantContext,
        target_id: TenantId,
    ) -> Result<Tenant, TenantManagementError> {
        if target_id == requesting.tenant_id() {
            return match self
                .tenants
                .find_by_id(target_id)
                .await
                .map_err(|e| TenantManagementError::Internal(e.to_string()))?
            {
                Some(tenant) => Ok(tenant),
                None => Err(TenantManagementError::NotFound),
            };
        }
        self.load_child(requesting, target_id).await
    }

    /// 割り当て済みのドメインを一覧する。
    pub async fn list_domains(
        &self,
        requesting: TenantContext,
        target_id: TenantId,
    ) -> Result<Vec<TenantDomain>, TenantManagementError> {
        let tenant = self.load_self_or_child(requesting, target_id).await?;
        self.tenant_domains
            .list_for_tenant(tenant.id)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))
    }

    /// ドメインを割り当てる。
    ///
    /// 一意性は**グローバル**なので、他テナントが押さえていても `Conflict` になる。どのテナントが
    /// 持っているかは返さない —— 他テナントの構成を、ドメインを総当たりして覗けるようにしない。
    pub async fn add_domain(
        &self,
        requesting: TenantContext,
        target_id: TenantId,
        raw_domain: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<TenantDomain, TenantManagementError> {
        let tenant = self.load_self_or_child(requesting, target_id).await?;
        let domain = validate_domain(raw_domain).map_err(TenantManagementError::Validation)?;
        let now = self.clock.now();
        let record = TenantDomain {
            id: self.ids.new_id(),
            tenant_id: tenant.id,
            domain,
            created_at: now,
            updated_at: now,
        };
        self.tenant_domains
            .create(&record)
            .await
            .map_err(|e| match e {
                DomainError::Conflict(_) => {
                    TenantManagementError::Conflict(MessageKey::new("api-tenant-domain-conflict"))
                }
                other => TenantManagementError::Internal(other.to_string()),
            })?;
        // 監査にはドメインを残す（PII ではなく、テナントの構成そのもの）。ログインをどのテナントへ
        // 向けるかを決める操作であり、権限付与と同じ重さで追跡できる必要がある。
        self.record_domain_event(
            AuditEventType::TenantDomainAdded,
            tenant.id,
            actor,
            &record.domain,
            ctx,
        )
        .await;
        Ok(record)
    }

    /// 割り当てを解除する。
    pub async fn remove_domain(
        &self,
        requesting: TenantContext,
        target_id: TenantId,
        domain_id: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), TenantManagementError> {
        let tenant = self.load_self_or_child(requesting, target_id).await?;
        // 監査へ残す値のため、消す前に読む（消えた後では何を解除したか分からない）。
        let removed = self
            .tenant_domains
            .list_for_tenant(tenant.id)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?
            .into_iter()
            .find(|d| d.id == domain_id)
            .ok_or(TenantManagementError::NotFound)?;
        if !self
            .tenant_domains
            .delete(tenant.id, domain_id)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?
        {
            return Err(TenantManagementError::NotFound);
        }
        self.record_domain_event(
            AuditEventType::TenantDomainRemoved,
            tenant.id,
            actor,
            &removed.domain,
            ctx,
        )
        .await;
        Ok(())
    }

    async fn record_domain_event(
        &self,
        event: AuditEventType,
        tenant_id: TenantId,
        actor: &AdminActor,
        domain: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                event,
                AuditResult::Success,
                Some(tenant_id),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("domain={domain}")),
                ctx,
            )
            .await;
    }
}

fn validate_name(name: String) -> Result<String, TenantManagementError> {
    let trimmed = name.trim().to_string();
    if trimmed.is_empty() {
        return Err(TenantManagementError::Validation(MessageKey::new(
            "api-tenant-name-empty",
        )));
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::tenant_membership::TenantMembership;
    use crate::domain::values::{MembershipStatus, MembershipType};
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 11, 12, 0, 0).unwrap()
    }

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    struct SeqIds(Mutex<u128>);
    impl IdGenerator for SeqIds {
        fn new_id(&self) -> Uuid {
            let mut n = self.0.lock().unwrap();
            *n += 1;
            Uuid::from_u128(*n)
        }
    }

    #[derive(Default)]
    struct CapturingSink {
        events: Mutex<Vec<AuditEvent>>,
    }
    #[async_trait]
    impl AuditLogSink for CapturingSink {
        async fn record(&self, event: &AuditEvent) -> DomainResult<()> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeTenants {
        rows: Mutex<Vec<Tenant>>,
    }
    #[async_trait]
    impl TenantRepository for FakeTenants {
        async fn create(&self, t: &Tenant) -> DomainResult<()> {
            self.rows.lock().unwrap().push(t.clone());
            Ok(())
        }
        async fn find_by_id(&self, id: TenantId) -> DomainResult<Option<Tenant>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|t| t.id == id)
                .cloned())
        }
        async fn find_root(&self) -> DomainResult<Option<Tenant>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|t| t.is_root())
                .cloned())
        }
        async fn list_children(&self, parent: TenantId) -> DomainResult<Vec<Tenant>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|t| t.parent_tenant_id == Some(parent))
                .cloned()
                .collect())
        }
        async fn update(&self, t: &Tenant) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(row) = rows.iter_mut().find(|r| r.id == t.id) {
                *row = t.clone();
            }
            Ok(())
        }
        async fn delete(&self, id: TenantId) -> DomainResult<()> {
            self.rows.lock().unwrap().retain(|t| t.id != id);
            Ok(())
        }
    }

    /// テナント開通 unit of work のフェイク。成功時は全行を「まとめて」記録し（原子性を模す）、
    /// `fail = true` なら何も書かずに失敗する（途中失敗＝全ロールバックの相当）。
    /// ドメインを持たないテナント（既定実装のまま）。既存のテストはドメイン経路を通らない。
    struct NoTenantDomains;

    #[async_trait]
    impl crate::domain::repositories::TenantDomainRepository for NoTenantDomains {}

    struct FakeProvisioning {
        tenants: Arc<FakeTenants>,
        memberships: Mutex<Vec<TenantMembership>>,
        granted: Mutex<Vec<(TenantId, Uuid, String)>>,
        fail: bool,
    }
    #[async_trait]
    impl TenantProvisioningRepository for FakeProvisioning {
        async fn provision(
            &self,
            tenant: &Tenant,
            admin_membership: &TenantMembership,
            admin_permission_code: &str,
            _granted_at: DateTime<Utc>,
        ) -> DomainResult<()> {
            if self.fail {
                return Err(DomainError::Repository(
                    "simulated provisioning failure".to_string(),
                ));
            }
            self.tenants.rows.lock().unwrap().push(tenant.clone());
            self.memberships
                .lock()
                .unwrap()
                .push(admin_membership.clone());
            self.granted.lock().unwrap().push((
                admin_membership.tenant_id,
                admin_membership.user_id,
                admin_permission_code.to_string(),
            ));
            Ok(())
        }
    }

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "corr-1".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    struct Harness {
        svc: TenantManagementService,
        tenants: Arc<FakeTenants>,
        provisioning: Arc<FakeProvisioning>,
        sink: Arc<CapturingSink>,
    }

    fn harness() -> Harness {
        harness_with(false)
    }

    fn harness_with(fail_provision: bool) -> Harness {
        let sink = Arc::new(CapturingSink::default());
        let audit = Arc::new(AuditService::new(sink.clone(), Arc::new(FixedClock(now()))));
        let tenants = Arc::new(FakeTenants::default());
        let provisioning = Arc::new(FakeProvisioning {
            tenants: tenants.clone(),
            memberships: Mutex::new(Vec::new()),
            granted: Mutex::new(Vec::new()),
            fail: fail_provision,
        });
        let svc = TenantManagementService::new(
            tenants.clone(),
            Arc::new(NoTenantDomains),
            provisioning.clone(),
            audit,
            Arc::new(FixedClock(now())),
            Arc::new(SeqIds(Mutex::new(0))),
        );
        Harness {
            svc,
            tenants,
            provisioning,
            sink,
        }
    }

    fn root() -> TenantContext {
        // root として作成側テナントを表す（parent 照合には使わない）。
        TenantContext::new(TenantId::from(Uuid::from_u128(0xAAAA)))
    }

    #[tokio::test]
    async fn create_tenant_adds_creator_as_bootstrap_guest_admin() {
        let h = harness();
        let actor = Uuid::new_v4();
        let tenant = h
            .svc
            .create_tenant(
                root(),
                CreateTenantCommand {
                    name: "  Acme  ".to_string(),
                },
                &AdminActor::User(actor),
                &ctx(),
            )
            .await
            .expect("created");

        assert_eq!(tenant.name, "Acme");
        assert_eq!(tenant.parent_tenant_id, Some(root().tenant_id()));
        // 新テナント scope で作成者へ idp.tenant.admin が付与される。
        let granted = h.provisioning.granted.lock().unwrap().clone();
        assert_eq!(
            granted,
            vec![(tenant.id, actor, "idp.tenant.admin".to_string())]
        );
        // 作成者の ACTIVE GUEST メンバーシップが同一 unit of work に含まれる。
        let memberships = h.provisioning.memberships.lock().unwrap();
        assert_eq!(memberships.len(), 1);
        assert_eq!(memberships[0].membership_type, MembershipType::Guest);
        assert_eq!(memberships[0].status, MembershipStatus::Active);
        assert_eq!(memberships[0].tenant_id, tenant.id);
        assert_eq!(memberships[0].user_id, actor);
        // 監査に tenant.created が記録され、初期管理者ユーザーは作られない（user.created は無し）。
        let events = h.sink.events.lock().unwrap();
        assert!(events
            .iter()
            .any(|e| e.event_type == AuditEventType::TenantCreated));
        assert!(events
            .iter()
            .all(|e| e.event_type != AuditEventType::UserCreated));
    }

    #[tokio::test]
    async fn provision_failure_leaves_no_tenant_and_no_success_audit() {
        let h = harness_with(true);
        let result = h
            .svc
            .create_tenant(
                root(),
                CreateTenantCommand {
                    name: "Acme".to_string(),
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await;
        assert!(matches!(result, Err(TenantManagementError::Internal(_))));
        // unit of work が失敗したらテナント・メンバーシップ・権限は一切残らない。
        assert!(h.tenants.rows.lock().unwrap().is_empty());
        assert!(h.provisioning.memberships.lock().unwrap().is_empty());
        assert!(h.provisioning.granted.lock().unwrap().is_empty());
        // 成功監査（tenant.created）も記録されない。
        assert!(h.sink.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_tenant_rejects_empty_name() {
        let h = harness();
        assert!(matches!(
            h.svc
                .create_tenant(
                    root(),
                    CreateTenantCommand {
                        name: "   ".to_string(),
                    },
                    &AdminActor::User(Uuid::new_v4()),
                    &ctx()
                )
                .await,
            Err(TenantManagementError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn get_update_delete_scope_to_direct_children() {
        let h = harness();
        let created = h
            .svc
            .create_tenant(
                root(),
                CreateTenantCommand {
                    name: "Child".to_string(),
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .unwrap();
        let child_id = created.id;

        // 別テナントからは見えない（NotFound）。
        let other = TenantContext::new(TenantId::from(Uuid::from_u128(0xBBBB)));
        assert!(matches!(
            h.svc.get_child(other, child_id).await,
            Err(TenantManagementError::NotFound)
        ));

        // 直下の子は取得できる。
        assert_eq!(
            h.svc.get_child(root(), child_id).await.unwrap().id,
            child_id
        );

        // 更新（表示名・状態）。
        let updated = h
            .svc
            .update_tenant(
                root(),
                child_id,
                UpdateTenantCommand {
                    name: Some("Renamed".to_string()),
                    status: Some(TenantStatus::Disabled),
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .unwrap();
        assert_eq!(updated.name, "Renamed");
        assert_eq!(updated.status, TenantStatus::Disabled);

        // 削除できる（子・ユーザーは fake では検査しないが list_children は空）。
        h.svc
            .delete_tenant(root(), child_id, &AdminActor::User(Uuid::new_v4()), &ctx())
            .await
            .expect("deleted");
        assert!(h
            .tenants
            .rows
            .lock()
            .unwrap()
            .iter()
            .all(|t| t.id != child_id));
    }

    #[tokio::test]
    async fn delete_rejects_tenant_with_children() {
        let h = harness();
        let parent = h
            .svc
            .create_tenant(
                root(),
                CreateTenantCommand {
                    name: "Parent".to_string(),
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .unwrap();
        // parent の下に孫を作る（parent を requesting として）。
        h.svc
            .create_tenant(
                TenantContext::new(parent.id),
                CreateTenantCommand {
                    name: "Grandchild".to_string(),
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .unwrap();

        assert!(matches!(
            h.svc
                .delete_tenant(root(), parent.id, &AdminActor::User(Uuid::new_v4()), &ctx())
                .await,
            Err(TenantManagementError::Conflict(_))
        ));
    }
}
