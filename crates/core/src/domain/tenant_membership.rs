//! TenantMemberships エンティティ（招待とゲスト参加。ADR-0009 §3）。
//!
//! HOME 行はユーザー作成時に自動生成する投影（所属元の単一の出所は `users.tenant_id`）。
//! GUEST 行は招待フローで作成し、`INVITED`（未承諾）→ `ACTIVE`（承諾済み）と遷移する。
#![allow(dead_code)]

use crate::domain::tenant::TenantId;
use crate::domain::values::{MembershipStatus, MembershipType};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct TenantMembership {
    /// 参加先テナント。
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    pub membership_type: MembershipType,
    pub status: MembershipStatus,
    /// 招待を作成した管理者ユーザー（GUEST のみ）。
    pub invited_by: Option<Uuid>,
    /// 招待トークンのハッシュ（`INVITED` の間のみ保持する）。
    pub invitation_token_hash: Option<String>,
    pub invitation_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TenantMembership {
    /// HOME メンバーシップ（ユーザー作成時に自動生成する投影。ADR-0009 §3）。
    pub fn new_home(tenant_id: TenantId, user_id: Uuid, now: DateTime<Utc>) -> Self {
        Self {
            tenant_id,
            user_id,
            membership_type: MembershipType::Home,
            status: MembershipStatus::Active,
            invited_by: None,
            invitation_token_hash: None,
            invitation_expires_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// 作成者を新テナントのブートストラップ管理者にするための、直接 `ACTIVE` な GUEST メンバーシップ
    /// （ADR-0009 §4）。招待フローを経ないため `invited_by`・トークンは持たない。テナント作成時に
    /// 作成者（root の system 管理者）へ `idp.tenant.admin` と併せて付与し、以後の初期設定を可能にする。
    pub fn new_active_guest(tenant_id: TenantId, user_id: Uuid, now: DateTime<Utc>) -> Self {
        Self {
            tenant_id,
            user_id,
            membership_type: MembershipType::Guest,
            status: MembershipStatus::Active,
            invited_by: None,
            invitation_token_hash: None,
            invitation_expires_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn is_home(&self) -> bool {
        self.membership_type == MembershipType::Home
    }

    pub fn is_active(&self) -> bool {
        self.status == MembershipStatus::Active
    }

    /// 一時停止中か（MT24）。停止中はアクセスできないが、メンバーシップ行と当該テナント scope の
    /// 権限行は残っており、再開すれば元の状態に戻る（解除＝削除との違い）。
    pub fn is_suspended(&self) -> bool {
        self.status == MembershipStatus::Suspended
    }

    /// 一時停止できる状態か（MT24）。GUEST の `ACTIVE` のみ。
    ///
    /// HOME は所属元そのもので、停止するとログインする先が無くなる（無効化は
    /// [`crate::application::user_lifecycle`] のアカウント無効化を使う）。`INVITED` は
    /// まだアクセスを持たないため止める対象が無い。
    pub fn can_be_suspended(&self) -> bool {
        !self.is_home() && self.status == MembershipStatus::Active
    }

    /// 停止から再開できる状態か（MT24）。
    pub fn can_be_resumed(&self) -> bool {
        !self.is_home() && self.status == MembershipStatus::Suspended
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn membership(membership_type: MembershipType, status: MembershipStatus) -> TenantMembership {
        TenantMembership {
            tenant_id: Uuid::now_v7().into(),
            user_id: Uuid::now_v7(),
            membership_type,
            status,
            invited_by: None,
            invitation_token_hash: None,
            invitation_expires_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn distinguishes_home_from_guest() {
        assert!(membership(MembershipType::Home, MembershipStatus::Active).is_home());
        assert!(!membership(MembershipType::Guest, MembershipStatus::Invited).is_home());
    }

    #[test]
    fn tracks_invitation_lifecycle() {
        assert!(!membership(MembershipType::Guest, MembershipStatus::Invited).is_active());
        assert!(membership(MembershipType::Guest, MembershipStatus::Active).is_active());
    }

    /// MT24: 停止中はアクセスできない（`is_active` が false）。
    #[test]
    fn suspended_guest_is_not_active() {
        let suspended = membership(MembershipType::Guest, MembershipStatus::Suspended);
        assert!(!suspended.is_active());
        assert!(suspended.is_suspended());
    }

    /// 停止できるのは GUEST の ACTIVE だけ。HOME は所属元そのもので、止めるとログイン先が無くなる。
    /// INVITED はまだアクセスを持たないため止める対象が無い。
    #[test]
    fn only_active_guests_can_be_suspended_and_only_suspended_ones_resumed() {
        let cases = [
            (MembershipType::Guest, MembershipStatus::Active, true, false),
            (
                MembershipType::Guest,
                MembershipStatus::Suspended,
                false,
                true,
            ),
            (
                MembershipType::Guest,
                MembershipStatus::Invited,
                false,
                false,
            ),
            (MembershipType::Home, MembershipStatus::Active, false, false),
            (
                MembershipType::Home,
                MembershipStatus::Suspended,
                false,
                false,
            ),
        ];
        for (kind, status, suspendable, resumable) in cases {
            let m = membership(kind, status);
            assert_eq!(m.can_be_suspended(), suspendable, "{kind:?}/{status:?}");
            assert_eq!(m.can_be_resumed(), resumable, "{kind:?}/{status:?}");
        }
    }
}
