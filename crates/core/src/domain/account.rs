//! Account: the general term for a principal that identifies itself to assay (ADR-0038 / ADR-0065).
//!
//! There are two kinds: **people** (`users` + tenant membership) and **service accounts** (`clients` that run only on
//! `client_credentials`). Identifiers, credentials and how to stop them differ by kind (ADR-0038 decision 2), but
//! the way of answering "who is this and what may it use" (admin notes, usable apps, listing) is held in the
//! same shape regardless of kind. The root of the inconsistencies was that these were built only in the shape of people (ADR-0065).

use crate::domain::account_note::AccountNote;
use crate::domain::error::DomainError;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_membership::TenantMember;
use crate::domain::values::ClientStatus;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A value pointing to one account (ADR-0059 decision 5, ADR-0065 decision 2).
///
/// App assignments (`application_assignments`) and admin notes (`account_notes`) hold it in the same shape:
/// a `kind` column, with exactly one of `user_id` / `client_id` filled.
///
/// ⚠ Behavior differs by kind (for assignments):
///
/// - "Everyone" (`EVERYONE`) includes **only people**. Service accounts are always assigned individually
/// - Assigning a person = may sign in (the check at code issuance looks only at people)
/// - Assigning a service account = may obtain tokens for that app's audience (the `resource` identity)
/// - Only people appear in the directory (self)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountRef {
    /// A person (`users.id`).
    User { user_id: Uuid },
    /// A service account (`clients.id` of a client with only `client_credentials`).
    ServiceAccount { client_row_id: Uuid },
}

impl AccountRef {
    /// The value stored in the DB `kind` column. This enum is the single source of allowed values.
    pub fn kind(&self) -> &'static str {
        self.account_kind().db_value()
    }

    /// Extracts only the kind.
    pub fn account_kind(&self) -> AccountKind {
        match self {
            Self::User { .. } => AccountKind::User,
            Self::ServiceAccount { .. } => AccountKind::ServiceAccount,
        }
    }

    /// `users.id` if a person.
    pub fn user_id(&self) -> Option<Uuid> {
        match self {
            Self::User { user_id } => Some(*user_id),
            Self::ServiceAccount { .. } => None,
        }
    }

    /// `clients.id` if a service account.
    pub fn client_row_id(&self) -> Option<Uuid> {
        match self {
            Self::User { .. } => None,
            Self::ServiceAccount { client_row_id } => Some(*client_row_id),
        }
    }
}

/// A value by which admin API paths refer to an account (ADR-0065).
///
/// People are referred to by internal ID, service accounts by `client_id` (the value people know), the same as
/// assignment requests (ADR-0059). Translation to [`AccountRef`] (`clients.id`) is done by the Application layer
/// after checking it is in the requested tenant and is a service account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountLocator<'a> {
    User { user_id: Uuid },
    ServiceAccount { client_id: &'a str },
}

/// Kind of account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountKind {
    User,
    ServiceAccount,
}

impl AccountKind {
    /// Ordering (the order of kinds in the response when listing "all").
    pub const ALL: [AccountKind; 2] = [AccountKind::User, AccountKind::ServiceAccount];

    /// Admin API vocabulary (`?kind=`, `kind` in responses). Same spelling as assignment requests (ADR-0059).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::ServiceAccount => "service_account",
        }
    }

    /// Value of the DB `kind` column (`application_assignments` / `account_notes`).
    pub fn db_value(&self) -> &'static str {
        match self {
            Self::User => "USER",
            Self::ServiceAccount => "SERVICE_ACCOUNT",
        }
    }

    /// Reads from the admin API vocabulary. Unknown values give `None` (the caller turns it into 400).
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "user" => Some(Self::User),
            "service_account" => Some(Self::ServiceAccount),
            _ => None,
        }
    }

    /// Reads from the value of the DB `kind` column.
    pub fn from_db(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "USER" => Ok(Self::User),
            "SERVICE_ACCOUNT" => Ok(Self::ServiceAccount),
            other => Err(DomainError::Repository(format!(
                "unknown account kind `{other}`"
            ))),
        }
    }
}

/// One service account (the read model the admin screen reads. ADR-0065).
#[derive(Debug, Clone)]
pub struct ServiceAccount {
    /// `clients.id` (the target of assignments and notes).
    pub client_row_id: Uuid,
    /// The issued `client_id` (the value people tell apart by. Also written in paths).
    pub client_id: String,
    /// Registered name.
    pub app_name: String,
    pub status: ClientStatus,
    pub created_at: DateTime<Utc>,
    /// The app that has this service account as its identity (binding) (ADR-0059 decision 1). `None` if none.
    ///
    /// ⚠ This is a different relationship from "usable apps" (assignments). Mixing them up means no admin token is issued.
    pub identity_of: Option<IdentityApplication>,
    /// Admin note. ⚠ **Not shown outside the admin screen.**
    pub note: Option<AccountNote>,
}

/// An app that has the service account as its identity (id and display name only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityApplication {
    pub application_id: Uuid,
    pub display_name: String,
}

/// One row of the list.
#[derive(Debug, Clone)]
pub enum Account {
    User(TenantMember),
    ServiceAccount(ServiceAccount),
}

impl Account {
    pub fn kind(&self) -> AccountKind {
        match self {
            Self::User(_) => AccountKind::User,
            Self::ServiceAccount(_) => AccountKind::ServiceAccount,
        }
    }
}

/// Filter conditions for the account list (values after the caller has clamped and normalized them).
#[derive(Debug, Clone)]
pub struct AccountFilter {
    pub tenant_id: TenantId,
    /// Kinds to list. ⚠ **Never empty** (if no kind is readable, the caller returns 403).
    pub kinds: Vec<AccountKind>,
    pub search: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

/// One page of the account list. `total` is the total count ignoring `limit` / `offset`.
#[derive(Debug, Clone)]
pub struct AccountPage {
    pub accounts: Vec<Account>,
    pub total: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_and_db_spellings_round_trip() {
        for kind in AccountKind::ALL {
            assert_eq!(AccountKind::parse(kind.as_str()), Some(kind));
            assert_eq!(AccountKind::from_db(kind.db_value()).unwrap(), kind);
        }
        assert_eq!(AccountKind::parse("USER"), None);
        assert!(AccountKind::from_db("user").is_err());
    }

    #[test]
    fn ref_kind_matches_the_db_value_used_by_assignments() {
        let user = AccountRef::User {
            user_id: Uuid::nil(),
        };
        let sa = AccountRef::ServiceAccount {
            client_row_id: Uuid::nil(),
        };
        assert_eq!(user.kind(), "USER");
        assert_eq!(sa.kind(), "SERVICE_ACCOUNT");
    }
}
