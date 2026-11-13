//! TenantMemberships entity (invitations and guest participation; ADR-0009 §3).
//!
//! HOME rows are a projection generated automatically at user creation (the single source of home
//! is `users.tenant_id`). GUEST rows are created by the invitation flow and transition `INVITED`
//! (not accepted) → `ACTIVE` (accepted).
#![allow(dead_code)]

use crate::domain::account_note::AccountNote;
use crate::domain::tenant::TenantId;
use crate::domain::values::{MembershipStatus, MembershipType, UserStatus};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// One entry of the member list (read model). Represents a user participating in the tenant,
/// whether HOME or GUEST. A display-only row joining membership and user, not an entity.
///
/// email / name are resolved for display without the home check (invitations are created by
/// internal ID, so only the minimum needed for the joined tenant's admin to identify the invitee is
/// returned).
#[derive(Debug, Clone)]
pub struct TenantMember {
    pub user_id: Uuid,
    pub email: Option<String>,
    /// Primary login identifier (username; since AP15b the registry's `primary_of_user` row is
    /// authoritative).
    ///
    /// Returns the display value (`display_value`) as is. Not the normalized value used for
    /// matching, because the list **must read in the spelling the user registered** (ADR-0025).
    /// `None` for users without a primary identifier (accounts created without a username).
    pub preferred_username: Option<String>,
    pub name: Option<String>,
    pub membership_type: MembershipType,
    pub status: MembershipStatus,
    /// State of the user account itself (ACTIVE / DISABLED / LOCKED). `None` for nonexistent users.
    /// Returned so the admin console's member list can show disabled state.
    pub user_status: Option<UserStatus>,
    /// Lock expiry due to failed logins (AP6). `None` means not locked.
    ///
    /// Returned separately from `user_status`. Locks are represented by `users.locked_until`, not
    /// `users.status` (`status = LOCKED` cannot be set by admin operations), and **whether it has
    /// expired must be judged at read time**. Folding it into the state column would keep showing
    /// "locked" even after the expiry passed.
    pub locked_until: Option<DateTime<Utc>>,
    /// Provisional registration (ADR-0064). The user has not yet set credentials via the setup
    /// link.
    pub pending_setup: bool,
    /// Expiry of the currently live (unused) setup link. Reissuing marks the previous link used, so
    /// the newest unused one is the current link. `None` if there is none.
    ///
    /// ⚠ **Whether it has expired is judged at read time** (same reason as `locked_until`). Someone
    /// whose provisional link expired cannot get in until an admin reissues it.
    pub setup_link_expires_at: Option<DateTime<Utc>>,
    /// Admin note (ADR-0063). `None` if empty. ⚠ **Never expose outside the admin screen.**
    pub note: Option<AccountNote>,
}

/// Filter conditions for the member list (MT22). The SQL is built by infrastructure.
///
/// `tenant_id` is required (not an `Option`) to prevent cross-tenant viewing. `search` is a partial
/// match on email address, name, and **username**; normalization (trim, empty to `None`) is done by
/// the Application layer before passing. Usernames are included because if the shown values could
/// not be searched, the column would be "visible but unsearchable".
#[derive(Debug, Clone)]
pub struct TenantMemberFilter {
    pub tenant_id: TenantId,
    /// When looking up one person by name (member detail screen). ⚠ **Do not combine with
    /// `search`** — naming is an exact match, a different question from partial-match filtering.
    pub user_id: Option<uuid::Uuid>,
    pub search: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

/// One page of the member list. `total` is the total matching count ignoring `limit` / `offset`,
/// so the screen can determine "N in total" and whether there is a next page.
#[derive(Debug, Clone)]
pub struct TenantMemberPage {
    pub members: Vec<TenantMember>,
    pub total: i64,
}

#[derive(Debug, Clone)]
pub struct TenantMembership {
    /// The joined tenant.
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    pub membership_type: MembershipType,
    pub status: MembershipStatus,
    /// The admin user who created the invitation (GUEST only).
    pub invited_by: Option<Uuid>,
    /// Hash of the invitation token (kept only while `INVITED`).
    pub invitation_token_hash: Option<String>,
    pub invitation_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TenantMembership {
    /// HOME membership (a projection generated automatically at user creation; ADR-0009 §3).
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

    /// A GUEST membership that is directly `ACTIVE`, to make the creator the bootstrap admin of the
    /// new tenant (ADR-0009 §4). It skips the invitation flow, so it has no `invited_by` or token.
    /// Granted at tenant creation to the creator (root's system admin) together with
    /// `idp.tenant.admin`, enabling the initial setup.
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

    /// Whether suspended (MT24). While suspended there is no access, but the membership row and the
    /// permission rows scoped to that tenant remain, and resuming restores the original state (the
    /// difference from removal = deletion).
    pub fn is_suspended(&self) -> bool {
        self.status == MembershipStatus::Suspended
    }

    /// Whether it can be suspended (MT24). Only GUEST `ACTIVE`.
    ///
    /// HOME is the home tenant itself; suspending it would leave nowhere to sign in (for disabling,
    /// use account disabling in [`crate::application::user_lifecycle`]). `INVITED` has no access
    /// yet, so there is nothing to stop.
    pub fn can_be_suspended(&self) -> bool {
        !self.is_home() && self.status == MembershipStatus::Active
    }

    /// Whether it can be resumed from suspension (MT24).
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

    /// MT24: no access while suspended (`is_active` is false).
    #[test]
    fn suspended_guest_is_not_active() {
        let suspended = membership(MembershipType::Guest, MembershipStatus::Suspended);
        assert!(!suspended.is_active());
        assert!(suspended.is_suspended());
    }

    /// Only GUEST ACTIVE can be suspended. HOME is the home tenant itself; stopping it leaves
    /// nowhere to sign in. INVITED has no access yet, so there is nothing to stop.
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
