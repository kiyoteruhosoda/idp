//! Answers an app's roster (ADR-0057 / ADR-0059). Read by the RP's periodic reconciliation (I7 of ADR-0049).
//!
//! # Whose roster
//!
//! ⚠ **Do not let the RP say.** If the calling principal is a service account bound as **an app's
//! identity**, that app's roster is returned (ADR-0059). "Which app does this service account belong to"
//! is a fact assay holds; trusting a `client_id` the RP put in the path would let anyone with the
//! permission read other apps' rosters.
//!
//! # What it answers
//!
//! "**Users allowed to use this app**", not the tenant's user list. It answers in the same shape regardless
//! of the assignment mode, and ⚠ **the mode is not revealed to the RP** (ADR-0054).
//!
//! # One rule
//!
//! Eligibility is decided by [`Application::roster_state`], whose content is the same
//! [`Application::admits`] as the decision (where codes are issued). The repository returns only facts: ⚠ if the list
//! disagrees with the decision, "on the roster but cannot get in" and "not on it but can get in" happen.
//!
//! # No deltas
//!
//! ⚠ **No `updated_since`.** A removed assignment disappears with its row, so it never shows in a delta, and an
//! added assignment does not move `users.updated_at`: the changes the query most wants to catch are the least visible.
//! Reconciliation runs over everything, and the fate of `sub`s the RP holds is asked via [`RosterQuery::Subjects`].

use crate::domain::admin_actor::AdminActor;
use crate::domain::application::{
    Application, ApplicationUser, ApplicationUserState, BindingTarget,
};
use crate::domain::paging::{Page, PageRequest, PagedResult};
use crate::domain::repositories::{ApplicationRepository, ApplicationUserQuery};
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::AssignmentMode;
use std::sync::Arc;
use uuid::Uuid;

/// Default number of rows per page.
pub const DEFAULT_PAGE_SIZE: i64 = 50;
/// Maximum rows per page (larger values are clamped).
pub const MAX_PAGE_SIZE: i64 = 200;
/// Maximum number of `sub`s whose fate can be asked at once.
///
/// ⚠ **Decided by URI length.** A `sub` is 36 chars, so 100 is about 3.7KB, safely within the request line
/// limit (default 8KB) of the front (nginx, cloudflared). If not enough, ask in parts.
pub const MAX_SUBJECTS: usize = 100;

#[derive(Debug, PartialEq, Eq)]
pub enum ApplicationUserDirectoryError {
    /// The calling principal is not a service account (e.g. an admin console user).
    ///
    /// The roster's self is "the app of the calling service account", so a user has nothing to answer for.
    NotAServiceAccount,
    /// The calling service account is not bound to any app's identity.
    ///
    /// ⚠ **Never return an empty roster.** Answering "nobody may use it" makes the RP stop everyone.
    NotBound,
    /// Exceeded the maximum number of `sub`s that can be asked at once.
    TooManySubjects,
    Internal(String),
}

/// What is being asked.
pub enum RosterQuery {
    /// One page of this app's candidates (tenant members for `EVERYONE`, users with an assignment
    /// for `INDIVIDUAL`).
    Page,
    /// The fate of `sub`s the RP holds. ⚠ **Only this can answer `unknown` (gone)**:
    /// people who are gone, being absent, never appear in the candidate list.
    Subjects(Vec<Uuid>),
}

pub struct ApplicationUserDirectoryService {
    applications: Arc<dyn ApplicationRepository>,
    roster: Arc<dyn ApplicationUserQuery>,
}

impl ApplicationUserDirectoryService {
    pub fn new(
        applications: Arc<dyn ApplicationRepository>,
        roster: Arc<dyn ApplicationUserQuery>,
    ) -> Self {
        Self {
            applications,
            roster,
        }
    }

    /// Looks up the roster of the calling service account's app (`self`).
    ///
    /// Resolution is the single path "principal -> service account identity -> app". ⚠ **Permission codes do
    /// not grant it**: being bound as the identity is the reason one may read that app's roster
    /// (handing out tenant-wide `idp.applications:read` would allow reading other apps' rosters too).
    pub async fn for_caller(
        &self,
        tenant: TenantContext,
        caller: &AdminActor,
        query: RosterQuery,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<PagedResult<ApplicationUser>, ApplicationUserDirectoryError> {
        let client_row_id = caller
            .client_row_id()
            .ok_or(ApplicationUserDirectoryError::NotAServiceAccount)?;
        let application = self
            .applications
            .find_by_binding_target(
                tenant.tenant_id(),
                BindingTarget::ServiceAccount { client_row_id },
            )
            .await
            .map_err(|e| ApplicationUserDirectoryError::Internal(e.to_string()))?
            .ok_or(ApplicationUserDirectoryError::NotBound)?;

        let page = PageRequest::clamped(limit, offset, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE);
        let items = match query {
            RosterQuery::Page => self.candidates(tenant, &application, page).await?,
            RosterQuery::Subjects(subs) => self.subjects(tenant, &application, &subs, page).await?,
        };
        Ok(PagedResult::new(items, page))
    }

    /// One page of candidates. ⚠ **The table queried depends on the mode** (the same split as the decision not
    /// querying assignments for `EVERYONE`; ADR-0054).
    async fn candidates(
        &self,
        tenant: TenantContext,
        application: &Application,
        page: PageRequest,
    ) -> Result<Page<ApplicationUser>, ApplicationUserDirectoryError> {
        let facts = match application.assignment_mode {
            AssignmentMode::Everyone => {
                self.roster
                    .list_tenant_members(tenant.tenant_id(), page)
                    .await
            }
            AssignmentMode::Individual => {
                self.roster
                    .list_assigned(tenant.tenant_id(), application.id, page)
                    .await
            }
        }
        .map_err(|e| ApplicationUserDirectoryError::Internal(e.to_string()))?;

        Ok(Page::new(
            facts
                .items
                .into_iter()
                .map(|row| ApplicationUser {
                    sub: row.sub,
                    state: application.roster_state(row.facts),
                })
                .collect(),
            facts.total,
        ))
    }

    /// The fate of the asked `sub`s. ⚠ **Every asked `sub` is always returned as one row** (if some `sub` did not
    /// come back, the caller could not tell "gone" from "missed").
    async fn subjects(
        &self,
        tenant: TenantContext,
        application: &Application,
        subs: &[Uuid],
        page: PageRequest,
    ) -> Result<Page<ApplicationUser>, ApplicationUserDirectoryError> {
        if subs.len() > MAX_SUBJECTS {
            return Err(ApplicationUserDirectoryError::TooManySubjects);
        }
        let facts = self
            .roster
            .facts_for_subs(tenant.tenant_id(), application.id, subs)
            .await
            .map_err(|e| ApplicationUserDirectoryError::Internal(e.to_string()))?;

        let mut answers: Vec<ApplicationUser> = subs
            .iter()
            .map(|sub| {
                let state = facts
                    .iter()
                    .find(|row| row.sub == *sub)
                    // No row = not a user of this tenant.
                    .map_or(ApplicationUserState::Unknown, |row| {
                        application.roster_state(row.facts)
                    });
                ApplicationUser { sub: *sub, state }
            })
            .collect();
        // Use the same order as the candidate list (`sub` ascending). Returning in request order would change
        // the order for the same query.
        answers.sort_by_key(|user| user.sub);
        answers.dedup_by_key(|user| user.sub);
        Ok(Page::from_all(answers, page))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::account::AccountRef;
    use crate::domain::application::{
        ApplicationAssignment, ApplicationBinding, ApplicationUserFacts, AssignedServiceAccount,
        AssignedUser,
    };
    use crate::domain::error::Result as DomainResult;
    use crate::domain::repositories::SubjectFacts;
    use crate::domain::tenant::TenantId;
    use crate::domain::values::{ApplicationStatus, UserStatus};
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 16, 0, 0, 0).unwrap()
    }

    fn tenant_id() -> TenantId {
        TenantId::from(Uuid::from_u128(2))
    }

    fn application(mode: AssignmentMode, status: ApplicationStatus) -> Application {
        Application {
            id: Uuid::from_u128(1),
            tenant_id: tenant_id(),
            display_name: "photonest".to_string(),
            status,
            assignment_mode: mode,
            created_at: now(),
            updated_at: now(),
        }
    }

    fn facts(user_status: UserStatus, active_member: bool, assigned: bool) -> ApplicationUserFacts {
        ApplicationUserFacts {
            user_status,
            pending_setup: false,
            active_member,
            assigned,
        }
    }

    /// Fake returning one app and fixed facts.
    struct Fake {
        application: Option<Application>,
        rows: Vec<SubjectFacts>,
    }

    #[async_trait]
    impl ApplicationRepository for Fake {
        async fn create(&self, _a: &Application) -> DomainResult<()> {
            Ok(())
        }
        async fn find_by_id(&self, _t: TenantId, _id: Uuid) -> DomainResult<Option<Application>> {
            Ok(self.application.clone())
        }
        async fn find_by_oidc_client_id(
            &self,
            _t: TenantId,
            _c: &str,
        ) -> DomainResult<Option<Application>> {
            Ok(None)
        }
        async fn find_by_binding_target(
            &self,
            _t: TenantId,
            target: BindingTarget,
        ) -> DomainResult<Option<Application>> {
            // ⚠ Looked up only by a service account identity (login identities get no answer).
            match target {
                BindingTarget::ServiceAccount { client_row_id }
                    if client_row_id == service_account() =>
                {
                    Ok(self.application.clone())
                }
                _ => Ok(None),
            }
        }
        async fn find_by_saml_entity_id(
            &self,
            _t: TenantId,
            _e: &str,
        ) -> DomainResult<Option<Application>> {
            Ok(None)
        }
        async fn list(&self, _t: TenantId) -> DomainResult<Vec<Application>> {
            Ok(Vec::new())
        }
        async fn update(
            &self,
            _t: TenantId,
            _id: Uuid,
            _n: &str,
            _s: ApplicationStatus,
            _m: AssignmentMode,
            _u: DateTime<Utc>,
        ) -> DomainResult<bool> {
            Ok(false)
        }
        async fn delete(&self, _t: TenantId, _id: Uuid) -> DomainResult<bool> {
            Ok(false)
        }
        async fn list_bindings(&self, _id: Uuid) -> DomainResult<Vec<ApplicationBinding>> {
            Ok(Vec::new())
        }
        async fn add_binding(&self, _b: &ApplicationBinding) -> DomainResult<()> {
            Ok(())
        }
        async fn remove_binding(&self, _a: Uuid, _b: Uuid) -> DomainResult<bool> {
            Ok(false)
        }
        async fn move_binding(
            &self,
            _b: Uuid,
            _from: Uuid,
            _to: Uuid,
            _at: DateTime<Utc>,
        ) -> DomainResult<bool> {
            Ok(false)
        }
        async fn list_tenant_bindings(
            &self,
            _t: TenantId,
        ) -> DomainResult<Vec<ApplicationBinding>> {
            Ok(Vec::new())
        }
        async fn is_assigned(&self, _a: Uuid, _u: Uuid) -> DomainResult<bool> {
            Ok(false)
        }
        async fn is_service_account_assigned(&self, _a: Uuid, _c: Uuid) -> DomainResult<bool> {
            Ok(false)
        }
        async fn list_assigned_service_accounts(
            &self,
            _a: Uuid,
        ) -> DomainResult<Vec<AssignedServiceAccount>> {
            Ok(Vec::new())
        }
        async fn list_assigned_users(&self, _a: Uuid) -> DomainResult<Vec<AssignedUser>> {
            Ok(Vec::new())
        }
        async fn list_account_assignments(
            &self,
            _tenant_id: TenantId,
            _account: crate::domain::account::AccountRef,
        ) -> DomainResult<Vec<crate::domain::application::AccountAssignment>> {
            Ok(Vec::new())
        }
        async fn count_assignments(&self, _a: Uuid) -> DomainResult<i64> {
            Ok(0)
        }
        async fn assign(&self, _a: &ApplicationAssignment) -> DomainResult<()> {
            Ok(())
        }
        async fn unassign(&self, _a: Uuid, _p: AccountRef) -> DomainResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl ApplicationUserQuery for Fake {
        async fn list_tenant_members(
            &self,
            _t: TenantId,
            page: PageRequest,
        ) -> DomainResult<Page<SubjectFacts>> {
            Ok(Page::from_all(self.rows.clone(), page))
        }
        async fn list_assigned(
            &self,
            _t: TenantId,
            _a: Uuid,
            page: PageRequest,
        ) -> DomainResult<Page<SubjectFacts>> {
            Ok(Page::from_all(self.rows.clone(), page))
        }
        async fn facts_for_subs(
            &self,
            _t: TenantId,
            _a: Uuid,
            subs: &[Uuid],
        ) -> DomainResult<Vec<SubjectFacts>> {
            Ok(self
                .rows
                .iter()
                .filter(|row| subs.contains(&row.sub))
                .copied()
                .collect())
        }
    }

    fn service(fake: Fake) -> ApplicationUserDirectoryService {
        let fake = Arc::new(fake);
        ApplicationUserDirectoryService::new(fake.clone(), fake)
    }

    fn context() -> TenantContext {
        TenantContext::new(tenant_id())
    }

    /// `clients.id` of the service account bound as the identity.
    fn service_account() -> Uuid {
        Uuid::from_u128(99)
    }

    fn caller() -> AdminActor {
        AdminActor::Client {
            id: service_account(),
            client_id: "wiki-machine".to_string(),
        }
    }

    /// A service account not bound to an identity **never gets an empty roster**. Returning one makes the RP stop everyone.
    #[tokio::test]
    async fn a_service_account_without_an_application_is_not_an_empty_roster() {
        let svc = service(Fake {
            application: Some(application(
                AssignmentMode::Individual,
                ApplicationStatus::Active,
            )),
            rows: Vec::new(),
        });
        let stranger = AdminActor::Client {
            id: Uuid::from_u128(98),
            client_id: "other-machine".to_string(),
        };
        let err = svc
            .for_caller(context(), &stranger, RosterQuery::Page, None, None)
            .await
            .unwrap_err();
        assert_eq!(err, ApplicationUserDirectoryError::NotBound);
    }

    /// A user (a person in the admin console) has no self.
    #[tokio::test]
    async fn a_user_has_no_own_application() {
        let svc = service(Fake {
            application: Some(application(
                AssignmentMode::Individual,
                ApplicationStatus::Active,
            )),
            rows: Vec::new(),
        });
        let err = svc
            .for_caller(
                context(),
                &AdminActor::User(Uuid::from_u128(7)),
                RosterQuery::Page,
                None,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err, ApplicationUserDirectoryError::NotAServiceAccount);
    }

    /// An asked `sub` always comes back as one row even if not in assay (= gone).
    #[tokio::test]
    async fn a_subject_that_is_gone_comes_back_as_unknown() {
        let here = Uuid::from_u128(10);
        let gone = Uuid::from_u128(11);
        let svc = service(Fake {
            application: Some(application(
                AssignmentMode::Individual,
                ApplicationStatus::Active,
            )),
            rows: vec![SubjectFacts {
                sub: here,
                facts: facts(UserStatus::Active, true, true),
            }],
        });
        let result = svc
            .for_caller(
                context(),
                &caller(),
                RosterQuery::Subjects(vec![here, gone]),
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.page.total, 2);
        assert_eq!(
            result.page.items,
            vec![
                ApplicationUser {
                    sub: here,
                    state: ApplicationUserState::Allowed
                },
                ApplicationUser {
                    sub: gone,
                    state: ApplicationUserState::Unknown
                },
            ]
        );
    }

    /// A stopped account is `blocked` even with an assignment (⚠ the binding is kept).
    #[tokio::test]
    async fn a_disabled_account_is_blocked_even_when_assigned() {
        let sub = Uuid::from_u128(10);
        let svc = service(Fake {
            application: Some(application(
                AssignmentMode::Individual,
                ApplicationStatus::Active,
            )),
            rows: vec![SubjectFacts {
                sub,
                facts: facts(UserStatus::Disabled, true, true),
            }],
        });
        let result = svc
            .for_caller(context(), &caller(), RosterQuery::Page, None, None)
            .await
            .unwrap();
        assert_eq!(result.page.items[0].state, ApplicationUserState::Blocked);
    }

    /// A stopped app returns **everyone as `blocked`** instead of candidates disappearing,
    /// so "could not look up" is not confused with "nobody may use it".
    #[tokio::test]
    async fn a_disabled_application_blocks_everyone_without_emptying_the_roster() {
        let sub = Uuid::from_u128(10);
        let svc = service(Fake {
            application: Some(application(
                AssignmentMode::Everyone,
                ApplicationStatus::Disabled,
            )),
            rows: vec![SubjectFacts {
                sub,
                facts: facts(UserStatus::Active, true, false),
            }],
        });
        let result = svc
            .for_caller(context(), &caller(), RosterQuery::Page, None, None)
            .await
            .unwrap();
        assert_eq!(result.page.total, 1);
        assert_eq!(result.page.items[0].state, ApplicationUserState::Blocked);
    }

    /// In an "everyone" app, members not currently participating (invited, suspended) are `blocked`.
    #[tokio::test]
    async fn everyone_mode_blocks_members_who_are_not_active() {
        let sub = Uuid::from_u128(10);
        let svc = service(Fake {
            application: Some(application(
                AssignmentMode::Everyone,
                ApplicationStatus::Active,
            )),
            rows: vec![SubjectFacts {
                sub,
                facts: facts(UserStatus::Active, false, false),
            }],
        });
        let result = svc
            .for_caller(context(), &caller(), RosterQuery::Page, None, None)
            .await
            .unwrap();
        assert_eq!(result.page.items[0].state, ApplicationUserState::Blocked);
    }

    #[tokio::test]
    async fn too_many_subjects_is_refused() {
        let svc = service(Fake {
            application: Some(application(
                AssignmentMode::Individual,
                ApplicationStatus::Active,
            )),
            rows: Vec::new(),
        });
        let subs: Vec<Uuid> = (0..=MAX_SUBJECTS as u128).map(Uuid::from_u128).collect();
        let err = svc
            .for_caller(
                context(),
                &caller(),
                RosterQuery::Subjects(subs),
                None,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err, ApplicationUserDirectoryError::TooManySubjects);
    }
}
