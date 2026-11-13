//! Resolves "the user who may be authenticated in this tenant" from the login field input (ADR-0009 §8).
//!
//! There are three paths that accept passwords (OIDC login [`crate::application::login`], portal
//! login [`crate::application::portal_login`], admin login [`crate::application::admin_login`];
//! five places counting re-verification on forced password change). All solve the same question, "whom does the value
//! entered on the login screen refer to", so the rule is unified here. Writing it in each path would let just the one
//! that was forgotten authenticate a different set.
//!
//! # Targets are "ACTIVE members of the tenant"
//!
//! Users who may be authenticated are those with an **ACTIVE membership in the tenant** (HOME or GUEST).
//! It isn't limited to the home tenant (HOME) because guests would get stuck if they couldn't sign in from the host
//! tenant's login screen —— the host's screen has no clue to ask "where is your home", and users can't get in
//! anywhere unless they type their home tenant ID into the URL. Passkey authentication already works by this rule
//! (`ensure_active_member` in [`crate::application::passkey_authentication`]); only passwords were still
//! limited to the home tenant.
//!
//! # Resolution order (home tenant -> home tenant decided by domain -> guest in host tenant)
//!
//! 1. The requested tenant's registry ([`UserRepository::find_by_login_identifier`]).
//! 2. If that misses and the input has the form `local@domain` with the domain assigned to one tenant,
//!    look up **only that tenant's registry** (ADR-0029's home realm discovery.
//!    [`UserRepository::find_member_by_login_identifier`]).
//! 3. If it still misses, resolve users with an ACTIVE GUEST membership in the requested tenant via the registry
//!    of their home tenant
//!    ([`UserRepository::find_active_guest_by_login_identifier`]). **Not resolved if the home tenant is
//!    `DISABLED`** —— disabling the home tenant is an operation that stops that organization's users, not one meant to
//!    leave a back door via host tenants (ADR-0009 §8. The same rule seen from the membership side is
//!    [`crate::domain::repositories::TenantMembershipRepository::is_active_member`], which passkey
//!    authentication, SSO restore and the admin console access check go through).
//!
//! **The order matters.** Looking up 1 and 3 together in one go would make the input "ambiguous" just because a guest
//! with the same user name joined, locking out even that tenant's HOME users. Deciding the home tenant first means
//! that if names collide in a host tenant, only the guest side loses out (guests can still sign in from their home
//! tenant's screen as before).
//!
//! 2 comes before 3 because a domain-qualified input states outright "who in which organization".
//! It is more precise than the scan for inputs that don't (bare user names), and **ambiguity can't arise in
//! principle** (only one tenant's registry is looked up, and within it one normalized value belongs to one person).
//! 3 remains because bare user names and unassigned domains (`gmail.com` etc.) don't hit 2;
//! dropping it would stop many guests from signing in from host tenants' screens. **2 is additive, not a replacement.**
//!
//! # Ambiguous input stops there (MT25)
//!
//! When 1 is **ambiguous** (hit several people), it must not proceed to 2. This used to
//! return `Option<User>`, with "missing" and "ambiguous" both collapsed to `None`, so input that was ambiguous
//! in the home tenant fell straight into guest resolution. No impersonation happened (a guest signs in as themselves
//! with their own password), but the two rules "don't let ambiguous through" and "the home tenant wins name contention
//! within the tenant" broke exactly where they were needed.
//!
//! [`LoginIdentifierMatch`] separates the two by type, so only `Unresolved(NotFound)` proceeds to the next step.
//! The same goes for step 2 (the domain path): if ambiguous within the decided home tenant, it doesn't fall
//! into the scan.
//!
//! # What is not decided here
//!
//! What authentication policies (AP2), locks and password policies apply to doesn't change. Policies are
//! looked up for **the requested tenant** (`list_enabled_for_tenant`), and locks and passwords are user attributes
//! (columns of `users`). When a guest signs in from a host tenant's screen, that screen's tenant's policies
//! apply —— the same as passkey authentication and the authorization flow's restore check
//! ([`crate::application::authorize`]), so conditions the host admin put on their tenant's login never
//! pass through just for guests.

use crate::domain::error::Result;
use crate::domain::login_identifier::{LoginIdentifierMatch, UnresolvedReason};
use crate::domain::repositories::{TenantDomainRepository, UserRepository};
use crate::domain::tenant::TenantId;
use crate::domain::tenant_domain::split_qualified_identifier;

/// Whether it may proceed to the next step (= whether it was "missing"). Both resolved and ambiguous stop there.
fn should_continue(m: &LoginIdentifierMatch) -> bool {
    matches!(
        m,
        LoginIdentifierMatch::Unresolved(UnresolvedReason::NotFound)
    )
}

/// Resolves, from the login field input, the user who may be authenticated in `tenant_id`.
///
/// The caller uniformly turns a failure to resolve into a credential error (without revealing nonexistence),
/// but the reason is returned as [`UnresolvedReason`] —— the value recorded in the audit differs.
pub async fn resolve_login_user(
    users: &dyn UserRepository,
    tenant_domains: &dyn TenantDomainRepository,
    tenant_id: TenantId,
    input: &str,
) -> Result<LoginIdentifierMatch> {
    // 1. The requested tenant's registry.
    let found = users.find_by_login_identifier(tenant_id, input).await?;
    if !should_continue(&found) {
        return Ok(found);
    }

    // 2. If the domain decides the home tenant, look up only that tenant.
    if let Some(found) = resolve_by_domain(users, tenant_domains, tenant_id, input).await? {
        return Ok(found);
    }

    // 3. Scan across joined guests.
    users
        .find_active_guest_by_login_identifier(tenant_id, input)
        .await
}

/// Decides the home tenant from the domain and resolves (ADR-0029). Returns `None` if it doesn't apply, and
/// the caller proceeds to the next step.
///
/// Within the decided tenant it looks up **two readings**. The order matters:
///
/// 1. **The input as-is** (`alice@corp.example`). Hits users who explicitly registered an email-kind
///    identifier.
/// 2. **The local part** (`alice`). The UPN-style interpretation: assigning the domain is itself a
///    declaration that "`<identifier>@corp.example` refers to a user of this tenant".
///
/// 1 is looked up first so users holding email-kind identifiers are **not redirected to someone else** by the UPN
/// interpretation. Within a tenant, the person holding `alice@corp.example` and the one holding `alice` may be different.
///
/// However, when **the home tenant is the requested tenant itself** (ADR-0029 §4), 1 is skipped. By the time this
/// step is reached, step 1 (the same registry looked up without the membership condition = a wider scope than here)
/// has already missed with the input as-is, so the same query always misses. No wasted round trip on the hot path.
///
/// 2 doesn't contradict "email login only when the tenant explicitly enables it" (ADR-0025 §5).
/// `alice@corp.example` doesn't mean mail reaches that address, and `users.email` isn't looked up.
/// Only the registry is looked up; what increases is **spellings**, not principals (the password is still required as before).
async fn resolve_by_domain(
    users: &dyn UserRepository,
    tenant_domains: &dyn TenantDomainRepository,
    tenant_id: TenantId,
    input: &str,
) -> Result<Option<LoginIdentifierMatch>> {
    // Input of the wrong shape doesn't even hit the DB (bare user names don't add to the hot path).
    let Some((local_part, domain)) = split_qualified_identifier(input) else {
        return Ok(None);
    };
    let Some(home_tenant_id) = tenant_domains.find_tenant_by_domain(&domain).await? else {
        return Ok(None);
    };

    // See the doc comment above. If home tenant = requested tenant, the input as-is isn't looked up again.
    let candidates: &[&str] = if home_tenant_id == tenant_id {
        &[local_part]
    } else {
        &[input, local_part]
    };
    for candidate in candidates.iter().copied() {
        let found = users
            .find_member_by_login_identifier(tenant_id, home_tenant_id, candidate)
            .await?;
        if !should_continue(&found) {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::DomainError;
    use crate::domain::repositories::TenantDomainRepository;
    use crate::domain::user::LoginFailureRecord;
    use crate::domain::user::User;
    use crate::domain::values::UserStatus;
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use uuid::Uuid;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 20, 0, 0, 0).unwrap()
    }

    fn user(tenant_id: TenantId) -> User {
        User {
            id: Uuid::now_v7(),
            tenant_id,
            sub: Uuid::now_v7(),
            email: "member@example.com".to_string(),
            email_verified: true,
            preferred_username: Some("member".to_string()),
            name: None,
            language: None,
            theme: None,
            password_hash: "hash".to_string(),
            must_change_password: false,
            password_changed_at: None,
            status: UserStatus::Active,
            pending_setup: false,
            failed_login_count: 0,
            locked_until: None,
            created_at: now(),
            updated_at: now(),
        }
    }

    /// A fake where resolution in the home tenant and as a guest can be swapped independently. `home_fails` is
    /// used to reproduce a repository failure.
    ///
    /// The default implementation of `find_by_login_identifier` (delegating to `find_by_username`) can only express
    /// "missing", so for the ambiguous cases this is overridden directly.
    ///
    /// `by_home_tenant` is for the domain path (ADR-0029): a table of "input looked up with the home tenant fixed ->
    /// result". This table lets us observe that lookups happen with both the input as-is and the local part.
    struct FakeUsers {
        home: LoginIdentifierMatch,
        guest: LoginIdentifierMatch,
        by_home_tenant: Vec<(String, LoginIdentifierMatch)>,
        home_fails: bool,
        guest_calls: AtomicUsize,
        member_lookups: Mutex<Vec<String>>,
    }

    impl Default for FakeUsers {
        fn default() -> Self {
            Self {
                home: LoginIdentifierMatch::not_found(),
                guest: LoginIdentifierMatch::not_found(),
                by_home_tenant: Vec::new(),
                home_fails: false,
                guest_calls: AtomicUsize::new(0),
                member_lookups: Mutex::new(Vec::new()),
            }
        }
    }

    /// A fake with exactly one domain assigned.
    struct FakeDomains {
        domain: String,
        tenant_id: TenantId,
    }

    #[async_trait]
    impl TenantDomainRepository for FakeDomains {
        async fn find_tenant_by_domain(&self, domain: &str) -> Result<Option<TenantId>> {
            Ok((domain == self.domain).then_some(self.tenant_id))
        }
    }

    /// A fake with no domain assigned (default implementation).
    struct NoDomains;

    #[async_trait]
    impl TenantDomainRepository for NoDomains {}

    #[async_trait]
    impl UserRepository for FakeUsers {
        async fn find_by_username(&self, _t: TenantId, _name: &str) -> Result<Option<User>> {
            unreachable!("resolution goes through find_by_login_identifier")
        }
        async fn find_by_login_identifier(
            &self,
            _tenant_id: TenantId,
            _input: &str,
        ) -> Result<LoginIdentifierMatch> {
            if self.home_fails {
                return Err(DomainError::Repository("db down".to_string()));
            }
            Ok(self.home.clone())
        }
        async fn find_active_guest_by_login_identifier(
            &self,
            _tenant_id: TenantId,
            _input: &str,
        ) -> Result<LoginIdentifierMatch> {
            self.guest_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.guest.clone())
        }
        async fn find_member_by_login_identifier(
            &self,
            _tenant_id: TenantId,
            _home_tenant_id: TenantId,
            input: &str,
        ) -> Result<LoginIdentifierMatch> {
            self.member_lookups.lock().unwrap().push(input.to_string());
            Ok(self
                .by_home_tenant
                .iter()
                .find(|(key, _)| key == input)
                .map(|(_, m)| m.clone())
                .unwrap_or_else(LoginIdentifierMatch::not_found))
        }
        async fn create(&self, _u: &User) -> Result<()> {
            unreachable!()
        }
        async fn find_by_id(&self, _id: Uuid) -> Result<Option<User>> {
            unreachable!()
        }
        async fn find_by_sub(&self, _s: Uuid) -> Result<Option<User>> {
            unreachable!()
        }
        async fn find_by_email(&self, _t: TenantId, _e: &str) -> Result<Option<User>> {
            unreachable!()
        }
        async fn update_login_state(
            &self,
            _id: Uuid,
            _count: i32,
            _locked_until: Option<DateTime<Utc>>,
        ) -> Result<()> {
            unreachable!()
        }
        async fn record_login_failure(
            &self,
            _id: Uuid,
            _lockout: crate::domain::authentication_policy::LockoutPolicy,
            _now: DateTime<Utc>,
        ) -> Result<LoginFailureRecord> {
            unreachable!()
        }
        async fn update_password(&self, _id: Uuid, _e: &str, _h: &str) -> Result<bool> {
            unreachable!()
        }
        async fn reset_password_forced(&self, _id: Uuid, _e: &str, _h: &str) -> Result<bool> {
            unreachable!()
        }
        async fn update_status(&self, _id: Uuid, _s: UserStatus) -> Result<()> {
            unreachable!()
        }
        async fn delete(&self, _id: Uuid) -> Result<()> {
            unreachable!()
        }
        async fn mark_email_verified(&self, _id: Uuid) -> Result<()> {
            unreachable!()
        }
        async fn update_language(&self, _id: Uuid, _l: Option<&str>) -> Result<()> {
            unreachable!()
        }
    }

    /// Extracts the resolved user id (`None` for ambiguous or missing).
    fn resolved_id(m: LoginIdentifierMatch) -> Option<Uuid> {
        m.into_user().map(|u| u.id)
    }

    /// A user resolved in the home tenant is returned as before, and no guest lookup happens (the order that keeps a
    /// joined guest with the same name from making the HOME user "ambiguous").
    #[tokio::test]
    async fn resolves_home_member_without_consulting_guests() {
        let tenant: TenantId = Uuid::now_v7().into();
        let home = user(tenant);
        let repo = FakeUsers {
            home: LoginIdentifierMatch::Resolved(home.clone()),
            guest: LoginIdentifierMatch::Resolved(user(Uuid::now_v7().into())),
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &NoDomains, tenant, "member")
            .await
            .unwrap();
        assert_eq!(resolved_id(resolved), Some(home.id));
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 0);
    }

    /// If the home tenant misses, resolve as an ACTIVE GUEST of the tenant.
    #[tokio::test]
    async fn falls_back_to_active_guest_of_the_requested_tenant() {
        let tenant: TenantId = Uuid::now_v7().into();
        let guest = user(Uuid::now_v7().into());
        let repo = FakeUsers {
            guest: LoginIdentifierMatch::Resolved(guest.clone()),
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &NoDomains, tenant, "member")
            .await
            .unwrap();
        assert_eq!(resolved_id(resolved), Some(guest.id));
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 1);
    }

    /// **If ambiguous in the home tenant, stop there** (the core of MT25). Falling into guest resolution would let a guest
    /// with the same value in, breaking both "don't let ambiguous through" and "the home tenant wins name contention".
    #[tokio::test]
    async fn ambiguous_home_identifier_does_not_fall_through_to_guests() {
        let tenant: TenantId = Uuid::now_v7().into();
        let repo = FakeUsers {
            home: LoginIdentifierMatch::ambiguous(),
            guest: LoginIdentifierMatch::Resolved(user(Uuid::now_v7().into())),
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &NoDomains, tenant, "member")
            .await
            .unwrap();
        assert!(matches!(
            resolved,
            LoginIdentifierMatch::Unresolved(UnresolvedReason::Ambiguous)
        ));
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 0);
    }

    /// Ambiguity on the guest side is also returned with its reason (two guests with the same value have joined;
    /// refuse without picking one).
    #[tokio::test]
    async fn ambiguous_guest_identifier_is_reported_as_ambiguous() {
        let repo = FakeUsers {
            guest: LoginIdentifierMatch::ambiguous(),
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &NoDomains, Uuid::now_v7().into(), "member")
            .await
            .unwrap();
        assert!(matches!(
            resolved,
            LoginIdentifierMatch::Unresolved(UnresolvedReason::Ambiguous)
        ));
    }

    /// `NotFound` if neither resolves (the caller turns it into a credential error).
    #[tokio::test]
    async fn returns_not_found_when_neither_resolves() {
        let tenant: TenantId = Uuid::now_v7().into();
        let repo = FakeUsers::default();
        let resolved = resolve_login_user(&repo, &NoDomains, tenant, "member")
            .await
            .unwrap();
        assert!(matches!(
            resolved,
            LoginIdentifierMatch::Unresolved(UnresolvedReason::NotFound)
        ));
    }

    // ── Domain path (ADR-0029) ─────────────────────────────────────────────────────

    fn domains(tenant_id: TenantId) -> FakeDomains {
        FakeDomains {
            domain: "corp.example".to_string(),
            tenant_id,
        }
    }

    /// Domain-qualified input is resolved **without going through the guest scan** (the main point of this ADR).
    /// It doesn't go through the scan, so however many guests with the same name join, they don't interfere.
    #[tokio::test]
    async fn a_domain_qualified_identifier_resolves_without_scanning_guests() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let member = user(home);
        let repo = FakeUsers {
            // Someone else is on the scan side. The domain path decides first, so this isn't consulted.
            guest: LoginIdentifierMatch::Resolved(user(Uuid::now_v7().into())),
            by_home_tenant: vec![(
                "alice".to_string(),
                LoginIdentifierMatch::Resolved(member.clone()),
            )],
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &domains(home), host, "alice@corp.example")
            .await
            .unwrap();
        assert_eq!(resolved_id(resolved), Some(member.id));
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 0);
    }

    /// Within the decided tenant, lookups go "input as-is -> local part". This order keeps users who explicitly
    /// registered an email-kind identifier from being redirected to someone else by the UPN interpretation.
    #[tokio::test]
    async fn the_full_input_wins_over_the_local_part() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let by_email = user(home);
        let by_username = user(home);
        let repo = FakeUsers {
            by_home_tenant: vec![
                (
                    "alice@corp.example".to_string(),
                    LoginIdentifierMatch::Resolved(by_email.clone()),
                ),
                (
                    "alice".to_string(),
                    LoginIdentifierMatch::Resolved(by_username.clone()),
                ),
            ],
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &domains(home), host, "alice@corp.example")
            .await
            .unwrap();
        assert_eq!(resolved_id(resolved), Some(by_email.id));
        // It doesn't go on to look up the local part.
        assert_eq!(
            *repo.member_lookups.lock().unwrap(),
            vec!["alice@corp.example".to_string()]
        );
    }

    /// If the input as-is misses, look up the local part (UPN form. `alice@corp.example` -> `alice`).
    #[tokio::test]
    async fn falls_back_to_the_local_part_as_a_upn() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let member = user(home);
        let repo = FakeUsers {
            by_home_tenant: vec![(
                "alice".to_string(),
                LoginIdentifierMatch::Resolved(member.clone()),
            )],
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &domains(home), host, "alice@corp.example")
            .await
            .unwrap();
        assert_eq!(resolved_id(resolved), Some(member.id));
        assert_eq!(
            *repo.member_lookups.lock().unwrap(),
            vec!["alice@corp.example".to_string(), "alice".to_string()]
        );
    }

    /// Unassigned domains (`gmail.com` etc.) don't hit the path and fall into the existing scan.
    /// **The domain path is additive, not a replacement.**
    #[tokio::test]
    async fn an_unassigned_domain_falls_through_to_the_guest_scan() {
        let host: TenantId = Uuid::now_v7().into();
        let guest = user(Uuid::now_v7().into());
        let repo = FakeUsers {
            guest: LoginIdentifierMatch::Resolved(guest.clone()),
            by_home_tenant: vec![(
                "alice".to_string(),
                LoginIdentifierMatch::Resolved(user(Uuid::now_v7().into())),
            )],
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &domains(host), host, "alice@other.example")
            .await
            .unwrap();
        assert_eq!(resolved_id(resolved), Some(guest.id));
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 1);
        assert!(repo.member_lookups.lock().unwrap().is_empty());
    }

    /// A bare user name doesn't even look up domains (doesn't add to the authentication hot path).
    #[tokio::test]
    async fn a_bare_identifier_never_consults_the_domain_registry() {
        let host: TenantId = Uuid::now_v7().into();
        let repo = FakeUsers::default();
        struct ExplodingDomains;
        #[async_trait]
        impl TenantDomainRepository for ExplodingDomains {
            async fn find_tenant_by_domain(&self, _domain: &str) -> Result<Option<TenantId>> {
                panic!("must not look up domains for bare input");
            }
        }

        let resolved = resolve_login_user(&repo, &ExplodingDomains, host, "alice")
            .await
            .unwrap();
        assert!(matches!(
            resolved,
            LoginIdentifierMatch::Unresolved(UnresolvedReason::NotFound)
        ));
    }

    /// If ambiguous within the decided tenant, stop there (don't fall into the scan; same rule as MT25).
    #[tokio::test]
    async fn an_ambiguous_result_in_the_resolved_home_tenant_stops_the_chain() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let repo = FakeUsers {
            guest: LoginIdentifierMatch::Resolved(user(Uuid::now_v7().into())),
            by_home_tenant: vec![(
                "alice@corp.example".to_string(),
                LoginIdentifierMatch::ambiguous(),
            )],
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &domains(home), host, "alice@corp.example")
            .await
            .unwrap();
        assert!(matches!(
            resolved,
            LoginIdentifierMatch::Unresolved(UnresolvedReason::Ambiguous)
        ));
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 0);
    }

    /// If the requested tenant's registry resolves it, the domain path doesn't run (step order).
    #[tokio::test]
    async fn the_requested_tenants_registry_still_wins() {
        let host: TenantId = Uuid::now_v7().into();
        let home_user = user(host);
        let repo = FakeUsers {
            home: LoginIdentifierMatch::Resolved(home_user.clone()),
            by_home_tenant: vec![(
                "alice".to_string(),
                LoginIdentifierMatch::Resolved(user(Uuid::now_v7().into())),
            )],
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &domains(host), host, "alice@corp.example")
            .await
            .unwrap();
        assert_eq!(resolved_id(resolved), Some(home_user.id));
        assert!(repo.member_lookups.lock().unwrap().is_empty());
    }

    /// When the requested tenant itself has a domain (ADR-0029 §4). `alice@x.example` misses at step 1
    /// and is then picked up by the local-part interpretation. **The input as-is isn't looked up again** —— step 1
    /// already looked up the same registry with a wider condition and missed, so it always misses.
    #[tokio::test]
    async fn the_requesting_tenants_own_domain_only_looks_up_the_local_part() {
        let host: TenantId = Uuid::now_v7().into();
        let member = user(host);
        let repo = FakeUsers {
            by_home_tenant: vec![(
                "alice".to_string(),
                LoginIdentifierMatch::Resolved(member.clone()),
            )],
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &domains(host), host, "alice@corp.example")
            .await
            .unwrap();
        assert_eq!(resolved_id(resolved), Some(member.id));
        assert_eq!(
            *repo.member_lookups.lock().unwrap(),
            vec!["alice".to_string()]
        );
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 0);
    }

    /// Repository failures are propagated as-is rather than swallowed (rounding to `NotFound` would turn a failure into
    /// "user missing" and also trigger the unnecessary guest lookup).
    #[tokio::test]
    async fn propagates_repository_errors_without_falling_back() {
        let repo = FakeUsers {
            home_fails: true,
            ..FakeUsers::default()
        };
        let err = resolve_login_user(&repo, &NoDomains, Uuid::now_v7().into(), "member")
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Repository(_)));
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 0);
    }
}
