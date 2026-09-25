//! アカウントの管理者メモを書く（ADR-0063 / ADR-0065）。
//!
//! - 人: `PUT /{tenant_id}/admin/members/{user_id}/note`
//! - サービスアカウント: `PUT /{tenant_id}/admin/service-accounts/{client_id}/note`
//!
//! 口は種別ごとに分かれる（書く権限が `idp.members:write` / `idp.clients:write` で違う）が、
//! 規則（上限・正規化・監査）はこのサービスにしか無い。読むのは一覧・詳細の結合
//! （[`crate::application::account_directory`]・[`crate::application::member_directory`]）で済むので、
//! ここは書き込みだけを持つ。
//!
//! ⚠ **監査にはメモの中身を載せない。** 経緯の自由記述には個人の事情が入る。残すのは「誰が・
//! 誰のメモを・書いたか消したか」だけにする（`UserProfileUpdated` が値を残さないのと同じ）。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::account::{AccountLocator, AccountRef};
use crate::domain::account_note::normalize_account_note;
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::message::MessageKey;
use crate::domain::repositories::{AccountNoteRepository, ClientRepository, TenantMemberQuery};
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_membership::TenantMemberFilter;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum AccountNoteError {
    /// 要求テナントのアカウントではない（他テナントの存在を推測させない）。
    NotFound,
    /// 長すぎる。
    Invalid(MessageKey),
    Internal(String),
}

pub struct AccountNoteService {
    members: Arc<dyn TenantMemberQuery>,
    clients: Arc<dyn ClientRepository>,
    notes: Arc<dyn AccountNoteRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl AccountNoteService {
    pub fn new(
        members: Arc<dyn TenantMemberQuery>,
        clients: Arc<dyn ClientRepository>,
        notes: Arc<dyn AccountNoteRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            members,
            clients,
            notes,
            audit,
            clock,
        }
    }

    /// メモを書く。空（空白だけ）なら消す。
    ///
    /// 人は HOME / GUEST を問わず書ける。メモはこのテナントの管理者の覚え書きであって、ゲストの
    /// 利用者そのもの（所属元の管理者しか触れない。ADR-0009 §3）を変えるものではない。
    pub async fn write(
        &self,
        tenant: TenantContext,
        target: AccountLocator<'_>,
        raw: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), AccountNoteError> {
        // ⚠ 検証を先にする（長すぎるなら、相手が居るかどうかを問い合わせる前に断る）。
        let text = normalize_account_note(raw).map_err(AccountNoteError::Invalid)?;
        let account = self.resolve(tenant, target).await?;
        let tenant_id = tenant.tenant_id();
        let subject = match target {
            AccountLocator::User { user_id } => format!("user={user_id}"),
            AccountLocator::ServiceAccount { client_id } => format!("service_account={client_id}"),
        };
        let reason = match text.as_deref() {
            Some(text) => {
                self.notes
                    .save(tenant_id, account, text, actor.user_id(), self.clock.now())
                    .await
                    .map_err(|e| AccountNoteError::Internal(e.to_string()))?;
                subject
            }
            None => {
                self.notes
                    .clear(tenant_id, account)
                    .await
                    .map_err(|e| AccountNoteError::Internal(e.to_string()))?;
                format!("{subject} cleared")
            }
        };
        self.audit
            .record(
                AuditEventType::AccountNoteUpdated,
                AuditResult::Success,
                Some(tenant_id),
                actor.user_id(),
                actor.client_id(),
                Some(&reason),
                ctx,
            )
            .await;
        Ok(())
    }

    /// 経路の値を、メモの相手（[`AccountRef`]）へ読み替える。
    ///
    /// - 人: 要求テナントのメンバーであること（メモはメンバーシップに付く。外部キーも拒む）
    /// - サービスアカウント: 要求テナントの client で、サービスアカウントであり、削除されていないこと。
    ///   ⚠ 連携先（ログイン用の client）にはメモを書かせない ——メモはアカウントの経緯であって、
    ///   連携先の設定ではない（ADR-0065 の決定 2）
    async fn resolve(
        &self,
        tenant: TenantContext,
        target: AccountLocator<'_>,
    ) -> Result<AccountRef, AccountNoteError> {
        match target {
            AccountLocator::User { user_id } => {
                let filter = TenantMemberFilter {
                    tenant_id: tenant.tenant_id(),
                    user_id: Some(user_id),
                    search: None,
                    limit: 1,
                    offset: 0,
                };
                let page = self
                    .members
                    .search(&filter)
                    .await
                    .map_err(|e| AccountNoteError::Internal(e.to_string()))?;
                if page.members.is_empty() {
                    return Err(AccountNoteError::NotFound);
                }
                Ok(AccountRef::User { user_id })
            }
            AccountLocator::ServiceAccount { client_id } => {
                let client = self
                    .clients
                    .find_by_client_id(tenant.tenant_id(), client_id)
                    .await
                    .map_err(|e| AccountNoteError::Internal(e.to_string()))?
                    .filter(|c| c.is_service_account() && !c.is_deleted())
                    .ok_or(AccountNoteError::NotFound)?;
                Ok(AccountRef::ServiceAccount {
                    client_row_id: client.id,
                })
            }
        }
    }
}
