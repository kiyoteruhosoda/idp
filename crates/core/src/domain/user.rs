//! Users entity (design spec §3.1 + ADR-0009 §2, §5).
#![allow(dead_code)]

use crate::domain::tenant::TenantId;
use crate::domain::values::UserStatus;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// State **after** recording one login failure ([`crate::domain::repositories::UserRepository::record_login_failure`]).
///
/// The increment and the lock decision happen in a single UPDATE, so callers only need to read this result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginFailureRecord {
    /// Consecutive failure count after recording.
    pub failed_login_count: i32,
    /// Lock expiry if a lock is in place (`None` otherwise).
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
}

impl LoginFailureRecord {
    /// Whether this failure put the account into the locked state.
    pub fn is_locked(&self) -> bool {
        self.locked_until.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct User {
    /// Internal identifier.
    pub id: Uuid,
    /// Owning (home) tenant. Always exactly one; immutable (ADR-0009 §2).
    pub tenant_id: TenantId,
    /// Externally exposed subject identifier (source of the ID Token `sub`).
    pub sub: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
    /// Display language setting (`ja` / `en`; NULL = unset; priority 2 in i18n spec §4; MT20).
    pub language: Option<String>,
    /// Color scheme setting (`light` / `dark` / `system`; NULL = unset). `system` means "chose to follow
    /// the OS", distinct from NULL's "has not chosen yet" (the former carries across devices).
    pub theme: Option<String>,
    /// argon2 password hash (PHC string).
    pub password_hash: String,
    /// Users created with an auto-generated password must change it at first login (ADR-0009 §5).
    pub must_change_password: bool,
    /// When the current password was set (the starting point AP7's expiry measures from). `None` = not recorded
    /// (users that existed before the column was added, or rows created by an old process). Read via [`User::password_set_at`].
    pub password_changed_at: Option<DateTime<Utc>>,
    pub status: UserStatus,
    /// Provisional registration (ADR-0064). `true` from creation by an admin until the user sets credentials via the setup link.
    ///
    /// **Orthogonal** to `status`. A provisional user can be disabled and re-enabled (and stays provisional).
    pub pending_setup: bool,
    pub failed_login_count: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Whether the account is active (can be issued tokens and log in).
    ///
    /// ⚠ **Provisional registration is not active** (ADR-0064). Login, tokens, the admin console and the directory
    /// all pass through this gate, so a provisional user cannot get in anywhere. Only the path for the user to finish
    /// setup is let through by [`Self::can_finish_setup`].
    pub fn is_active(&self) -> bool {
        self.status == UserStatus::Active && !self.pending_setup
    }

    /// Whether credentials may be set via the setup link (ADR-0062 / ADR-0064).
    ///
    /// Disabled users are rejected even if provisional (otherwise a stopped user could get back in with the link at hand).
    pub fn can_finish_setup(&self) -> bool {
        self.status == UserStatus::Active
    }

    /// Whether locked as of the given time.
    pub fn is_locked_at(&self, now: DateTime<Utc>) -> bool {
        matches!(self.locked_until, Some(until) if until > now)
    }

    /// When the current password was set. If not recorded, the **account creation time** is assumed (AP7).
    ///
    /// Not rounding "not recorded" to "never expires" is because that would put only users that existed before
    /// the column was added outside expiry. The oldest passwords should be the most subject to expiry, so the
    /// check leans on the earliest evidence of "existed at least by this time" (the creation time).
    pub fn password_set_at(&self) -> DateTime<Utc> {
        self.password_changed_at.unwrap_or(self.created_at)
    }
}

#[cfg(test)]
mod pending_setup_tests {
    use super::*;

    fn user(status: UserStatus, pending_setup: bool) -> User {
        let now = Utc::now();
        User {
            id: Uuid::nil(),
            tenant_id: Uuid::nil().into(),
            sub: Uuid::nil(),
            email: "a@example.com".to_string(),
            email_verified: true,
            preferred_username: None,
            name: None,
            language: None,
            theme: None,
            password_hash: String::new(),
            must_change_password: false,
            password_changed_at: None,
            status,
            pending_setup,
            failed_login_count: 0,
            locked_until: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// ADR-0064: provisional registration is not active. Only the path for finishing setup lets it through.
    #[test]
    fn a_pending_user_is_not_active_but_may_finish_setup() {
        let pending = user(UserStatus::Active, true);
        assert!(!pending.is_active());
        assert!(pending.can_finish_setup());

        let done = user(UserStatus::Active, false);
        assert!(done.is_active());
        assert!(done.can_finish_setup());
    }

    /// A disabled user cannot finish setup even if provisional.
    #[test]
    fn a_disabled_user_may_not_finish_setup() {
        assert!(!user(UserStatus::Disabled, true).can_finish_setup());
        assert!(!user(UserStatus::Disabled, false).is_active());
    }
}
