//! メンバーの管理者メモを書く（`PUT /{tenant_id}/admin/members/{user_id}/note`。ADR-0063）。
//!
//! 読むのはメンバー一覧・詳細（[`crate::application::member_directory`]）の結合で済むので、
//! ここは書き込みだけを持つ。
//!
//! ⚠ **監査にはメモの中身を載せない。** 経緯の自由記述には個人の事情が入る。残すのは「誰が・
//! 誰のメモを・書いたか消したか」だけにする（`UserProfileUpdated` が値を残さないのと同じ）。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::member_note::normalize_member_note;
use crate::domain::message::MessageKey;
use crate::domain::repositories::{MemberNoteRepository, TenantMemberQuery};
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_membership::TenantMemberFilter;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
pub enum MemberNoteError {
    /// 要求テナントのメンバーではない（他テナントの利用者の存在を推測させない）。
    NotFound,
    /// 長すぎる。
    Invalid(MessageKey),
    Internal(String),
}

pub struct MemberNoteService {
    members: Arc<dyn TenantMemberQuery>,
    notes: Arc<dyn MemberNoteRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl MemberNoteService {
    pub fn new(
        members: Arc<dyn TenantMemberQuery>,
        notes: Arc<dyn MemberNoteRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            members,
            notes,
            audit,
            clock,
        }
    }

    /// メモを書く。空（空白だけ）なら消す。
    ///
    /// HOME / GUEST を問わず書ける。メモはこのテナントの管理者の覚え書きであって、ゲストの
    /// 利用者そのもの（所属元の管理者しか触れない。ADR-0009 §3）を変えるものではない。
    pub async fn write(
        &self,
        tenant: TenantContext,
        user_id: Uuid,
        raw: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), MemberNoteError> {
        let text = normalize_member_note(raw).map_err(MemberNoteError::Invalid)?;
        self.require_member(tenant, user_id).await?;
        let tenant_id = tenant.tenant_id();
        let reason = match text.as_deref() {
            Some(text) => {
                self.notes
                    .save(tenant_id, user_id, text, actor.user_id(), self.clock.now())
                    .await
                    .map_err(|e| MemberNoteError::Internal(e.to_string()))?;
                format!("member={user_id}")
            }
            None => {
                self.notes
                    .clear(tenant_id, user_id)
                    .await
                    .map_err(|e| MemberNoteError::Internal(e.to_string()))?;
                format!("member={user_id} cleared")
            }
        };
        self.audit
            .record(
                AuditEventType::TenantMemberNoteUpdated,
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

    async fn require_member(
        &self,
        tenant: TenantContext,
        user_id: Uuid,
    ) -> Result<(), MemberNoteError> {
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
            .map_err(|e| MemberNoteError::Internal(e.to_string()))?;
        if page.members.is_empty() {
            return Err(MemberNoteError::NotFound);
        }
        Ok(())
    }
}
