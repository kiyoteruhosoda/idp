//! Application: **the level RPs hang from** (ADR-0054).
//!
//! One row represents "one app as seen by users". OIDC `clients` and SAML
//! `saml_service_providers` are only **how that app connects** (binding).
//!
//! # Why a level is needed above protocol settings
//!
//! `clients` and `saml_service_providers` do not reference each other. So the same app connecting via both OIDC and
//! SAML cannot be expressed, and authentication policy, consent, permissions, audiences and back-channel logout delivery
//! **all attach only to the OIDC side** (MFA cannot be required for SAML apps). Hanging user assignments from
//! `clients` would just add a 6th item to this list.
//!
//! # Assignments have no roles
//!
//! [`ApplicationAssignment`] carries only one bit: "may use". What one may do inside the app
//! is held by the RP (ADR-0033 / ADR-0049 I6). Whether to have a role column is **the shape of the
//! model**, not something that can be chosen per app.

use crate::domain::account::AccountRef;
use crate::domain::message::MessageKey;
use crate::domain::tenant::TenantId;
use crate::domain::values::{ApplicationStatus, AssignmentMode, ClientStatus, UserStatus};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Column limit of `applications.display_name`.
pub const DISPLAY_NAME_MAX_LEN: usize = 255;

/// One app (`applications` table).
#[derive(Debug, Clone)]
pub struct Application {
    pub id: Uuid,
    /// The tenant that owns the app. Not shared across tenants (ADR-0009 §1).
    pub tenant_id: TenantId,
    /// The name shown on screens and in refusal messages.
    pub display_name: String,
    pub status: ApplicationStatus,
    pub assignment_mode: AssignmentMode,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The answer to "may this user use this app" (ADR-0054).
///
/// The decision is made **after authentication**. We do not know who it is until authentication, so this is not an implementation
/// convenience but a necessity of ordering. That is exactly why refusal is told on assay's screen rather than returned to the RP:
/// from the user's view "I got in and was then rejected", so rejecting silently would be indistinguishable from an outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationAccess {
    /// May use.
    Allowed,
    /// The app itself is stopped.
    Disabled,
    /// The app is running, but this user has no assignment.
    NotAssigned,
}

impl ApplicationAccess {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// Reason recorded in audit logs and structured logs (operating language = English).
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Disabled => "application_disabled",
            Self::NotAssigned => "not_assigned",
        }
    }
}

impl Application {
    /// Takes whether an assignment exists and returns allow/deny (pure function. The caller queries the DB).
    ///
    /// `assigned` is taken as an argument even for `EVERYONE` so the caller can **look at the mode and skip
    /// the query** ([`Self::needs_assignment_lookup`]). Querying the DB here would make the decision impure,
    /// and a wasted query would run every time for "everyone" apps.
    pub fn admits(&self, assigned: bool) -> ApplicationAccess {
        if self.status != ApplicationStatus::Active {
            return ApplicationAccess::Disabled;
        }
        match self.assignment_mode {
            AssignmentMode::Everyone => ApplicationAccess::Allowed,
            AssignmentMode::Individual if assigned => ApplicationAccess::Allowed,
            AssignmentMode::Individual => ApplicationAccess::NotAssigned,
        }
    }

    /// Whether a **service account** may use this app (ADR-0059 decisions 5, 6).
    ///
    /// "Using" means obtaining tokens for this app's audience (the `resource` identity).
    /// Token issuance (`client_credentials` + `resource`) and the account screen read this same rule:
    /// ⚠ if the screen answered with a different rule, "shown as usable but no token is issued" would happen.
    ///
    /// ⚠ **Does not look at the assignment mode.** "Everyone" (`EVERYONE`) includes only people;
    /// service accounts are always assigned individually.
    pub fn admits_service_account(&self, assigned: bool) -> ApplicationAccess {
        if self.status != ApplicationStatus::Active {
            ApplicationAccess::Disabled
        } else if assigned {
            ApplicationAccess::Allowed
        } else {
            ApplicationAccess::NotAssigned
        }
    }

    /// Whether the decision needs an assignment query (`EVERYONE` does not).
    pub fn needs_assignment_lookup(&self) -> bool {
        self.assignment_mode == AssignmentMode::Individual
    }

    /// Whether it can be used as the target of new tokens or assertions.
    pub fn is_active(&self) -> bool {
        self.status == ApplicationStatus::Active
    }
}

/// Validates an app's display name and returns the value to store.
///
/// Returned as translation keys, consistent with the other admin APIs (translation happens in the Presentation layer).
pub fn validate_display_name(raw: &str) -> Result<String, MessageKey> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(MessageKey::new("api-application-name-required"));
    }
    // The column is VARCHAR(255) = **255 characters**, so check characters, not bytes
    // (checking bytes would miss short names containing non-ASCII).
    if value.chars().count() > DISPLAY_NAME_MAX_LEN {
        return Err(MessageKey::with_value(
            "api-application-name-too-long",
            DISPLAY_NAME_MAX_LEN.to_string(),
        ));
    }
    Ok(value.to_string())
}

/// An app identity (the counterpart of a binding. ADR-0059).
///
/// There are 4 kinds of ways an app shows up to assay as "itself". In all of them **one counterpart belongs to only one
/// app** (DB UNIQUE): if it could belong to two apps, it would be undecidable which app a request from that counterpart
/// belongs to.
///
/// It is held as an enum rather than two nullable columns to eliminate by type the state "OIDC but holding an SP",
/// which must not be representable (the DB says the same with a CHECK constraint).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingTarget {
    /// An OIDC RP for sign-in (`clients.id`. The surrogate key, not `client_id`).
    Oidc { client_row_id: Uuid },
    /// A SAML SP (`saml_service_providers.id`).
    Saml { service_provider_id: Uuid },
    /// The service account the app itself uses to call assay (`clients.id` of a `client_credentials` client).
    ///
    /// ⚠ **A service account is not an app.** It is one of the app's identities (e.g. the client wiki uses when
    /// fetching the directory is an identity of the app wiki). The directory's self endpoint decides the app from this identity of
    /// the calling client.
    ServiceAccount { client_row_id: Uuid },
    /// The audience of the app's API (`resources.id`. The value placed in a token's `aud`. ADR-0042).
    Resource { resource_id: Uuid },
}

impl BindingTarget {
    /// The value stored in the DB `kind` column. This enum is the single source of allowed values.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Oidc { .. } => "oidc",
            Self::Saml { .. } => "saml",
            Self::ServiceAccount { .. } => "service_account",
            Self::Resource { .. } => "resource",
        }
    }

    /// The counterpart's surrogate key (one, regardless of kind).
    pub fn target_id(&self) -> Uuid {
        match self {
            Self::Oidc { client_row_id } | Self::ServiceAccount { client_row_id } => *client_row_id,
            Self::Saml {
                service_provider_id,
            } => *service_provider_id,
            Self::Resource { resource_id } => *resource_id,
        }
    }
}

/// App <-> identity (`application_bindings` table). 0..N per app.
#[derive(Debug, Clone)]
pub struct ApplicationBinding {
    pub id: Uuid,
    pub application_id: Uuid,
    pub target: BindingTarget,
    pub created_at: DateTime<Utc>,
}

/// App x principal (`application_assignments` table).
///
/// ⚠ No roles. Only one bit, "may use", is carried here.
#[derive(Debug, Clone)]
pub struct ApplicationAssignment {
    pub id: Uuid,
    pub application_id: Uuid,
    pub principal: AccountRef,
    pub assigned_at: DateTime<Utc>,
    /// The admin who assigned it (the source, for audit). `None` for migrations or via a machine.
    pub assigned_by: Option<Uuid>,
}

/// One assigned service account row (the read model read by the admin API and screens).
#[derive(Debug, Clone)]
pub struct AssignedServiceAccount {
    pub client_row_id: Uuid,
    /// The issued `client_id` (the value people tell apart by).
    pub client_id: String,
    /// The client's registered name.
    pub app_name: String,
    pub client_status: ClientStatus,
    pub assigned_at: DateTime<Utc>,
}

/// One assigned user row (the read model read by the admin API and screens).
///
/// It is separate from the assignment row ([`ApplicationAssignment`]) because **the question differs**.
/// That one is a value for writing "who was assigned", and this one is a value for people to read "who is assigned";
/// name and email exist only in `users`, so they are read together in one query
/// (looking users up one by one would add round trips proportional to the directory length).
#[derive(Debug, Clone)]
pub struct AssignedUser {
    pub user_id: Uuid,
    /// The token's subject identifier. The key for matching against the RP's directory (ADR-0049).
    pub sub: Uuid,
    pub email: String,
    pub name: Option<String>,
    /// State of the user account itself. ⚠ **Assignments of stopped users remain**, so that
    /// the directory need not be rebuilt when they come back; whether they can get in is decided separately by the user's state.
    pub status: UserStatus,
    pub assigned_at: DateTime<Utc>,
}

/// One assignment attached to an account (so the account screen can show "usable apps".
/// ADR-0063 / ADR-0065).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountAssignment {
    pub application_id: Uuid,
    pub assigned_at: DateTime<Utc>,
}

/// One directory row (ADR-0057). The read model read by RPs' periodic reconciliation.
///
/// ⚠ **Only `sub` and state are carried.** Copies of attributes are handed over at every sign-in
/// (ADR-0049 I5), so this is an inventory endpoint, not an attribute distribution endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationUser {
    /// The token's subject identifier. The key for matching against the RP's directory (`federated_identities`).
    pub sub: Uuid,
    pub state: ApplicationUserState,
}

/// "May this person use this app now": split into 3 by **the action the RP takes** (ADR-0057).
///
/// ⚠ **Reasons are not returned in detail.** Separating "no assignment" from "account stopped" would
/// leak the assignment mode to the RP (ADR-0054 "do not tell RPs the mode"), and ⚠ **the RP's action is
/// the same for both**: do not let in, keep the link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationUserState {
    /// May use now.
    Allowed,
    /// Exists in assay but cannot use it now. ⚠ **Keep the link** (they may come back).
    Blocked,
    /// Not a user of this tenant (= gone). The link may be dropped as well.
    Unknown,
}

impl ApplicationUserState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Blocked => "blocked",
            Self::Unknown => "unknown",
        }
    }
}

/// **Facts** read from the DB to build the directory (no judgment. ADR-0057 decision 4).
///
/// Allow/deny is decided by [`Application::admits`]: if the decision (code issuance point) and the list had separate rules,
/// ⚠ **"in the directory but cannot get in" or "not in it but can get in"** would happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationUserFacts {
    /// State of the user account itself.
    pub user_status: UserStatus,
    /// Whether provisionally registered (ADR-0064). The user has not chosen credentials yet, so cannot sign in.
    pub pending_setup: bool,
    /// Whether the membership in the requested tenant is **active**.
    pub active_member: bool,
    /// Whether there is an assignment row for this app.
    pub assigned: bool,
}

impl Application {
    /// Decides the directory state from the facts (ADR-0057).
    ///
    /// ⚠ **Do not add conditions the decision does not have.** `INDIVIDUAL` does not look at membership because
    /// [`Self::admits`] does not, and if only the list were stricter it would drift toward "not in the directory but can get in".
    /// `EVERYONE` looks at membership because "everyone" refers only to those within the tenant
    /// (ADR-0054).
    pub fn roster_state(&self, facts: ApplicationUserFacts) -> ApplicationUserState {
        // Stopped users and provisionally registered users cannot sign in at all. This takes effect before whether there is an assignment
        // (on the decision side, `User::is_active` refuses both).
        if facts.user_status != UserStatus::Active || facts.pending_setup {
            return ApplicationUserState::Blocked;
        }
        if self.assignment_mode == AssignmentMode::Everyone && !facts.active_member {
            return ApplicationUserState::Blocked;
        }
        if self.admits(facts.assigned).is_allowed() {
            ApplicationUserState::Allowed
        } else {
            ApplicationUserState::Blocked
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(status: ApplicationStatus, mode: AssignmentMode) -> Application {
        let now = Utc::now();
        Application {
            id: Uuid::nil(),
            tenant_id: TenantId::from(Uuid::nil()),
            display_name: "photonest".to_string(),
            status,
            assignment_mode: mode,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn everyone_admits_without_an_assignment() {
        let a = app(ApplicationStatus::Active, AssignmentMode::Everyone);
        assert_eq!(a.admits(false), ApplicationAccess::Allowed);
        assert!(!a.needs_assignment_lookup());
    }

    #[test]
    fn individual_needs_the_row() {
        let a = app(ApplicationStatus::Active, AssignmentMode::Individual);
        assert_eq!(a.admits(false), ApplicationAccess::NotAssigned);
        assert_eq!(a.admits(true), ApplicationAccess::Allowed);
        assert!(a.needs_assignment_lookup());
    }

    /// A stopped app does not let anyone through, even with an assignment or when open to everyone.
    #[test]
    fn a_disabled_application_admits_nobody() {
        for mode in [AssignmentMode::Everyone, AssignmentMode::Individual] {
            let a = app(ApplicationStatus::Disabled, mode);
            assert_eq!(a.admits(true), ApplicationAccess::Disabled);
        }
    }

    #[test]
    fn display_name_is_trimmed_and_bounded() {
        assert_eq!(validate_display_name("  photonest  ").unwrap(), "photonest");
        assert!(validate_display_name("   ").is_err());
        let long: String = "あ".repeat(DISPLAY_NAME_MAX_LEN + 1);
        assert!(validate_display_name(&long).is_err());
    }

    /// ADR-0064: a provisionally registered person is "cannot use" in the directory even with an assignment (since they cannot sign in).
    #[test]
    fn a_pending_user_is_blocked_on_the_roster() {
        let application = app(ApplicationStatus::Active, AssignmentMode::Everyone);
        let facts = ApplicationUserFacts {
            user_status: UserStatus::Active,
            pending_setup: true,
            active_member: true,
            assigned: true,
        };
        assert_eq!(
            application.roster_state(facts),
            ApplicationUserState::Blocked
        );
        let facts = ApplicationUserFacts {
            pending_setup: false,
            ..facts
        };
        assert_eq!(
            application.roster_state(facts),
            ApplicationUserState::Allowed
        );
    }
}
