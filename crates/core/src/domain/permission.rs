//! Value representation of permissions (permission codes) held by users and clients, and their
//! implications (ADR-0006 / ADR-0037).
//!
//! "Permissions held by a principal", on a **separate axis** from OIDC scopes
//! (`domain::values::Scope`, claim control). Permission codes grow with operations and are
//! **master-driven = data**, so they are not a fixed Rust enum (ADR-0006 §5). The value object is a
//! `String` wrapper representing a namespaced code.
//!
//! On the other hand, **implications between codes** (`idp.tenant.admin` includes `idp.users:read`,
//! `:write` includes `:read`) are decision logic, not data. Holding an implication table in the DB
//! would split decisions between the DB and the app, so this module is the single source
//! (ADR-0037).
#![allow(dead_code)]

use crate::domain::error::DomainError;

/// Tenant management permission code (scope = that tenant). Needed to log in to the admin console
/// and for admin operations. The higher code implying all fine-grained codes
/// ([`TENANT_MANAGEMENT_CODES`]).
pub const TENANT_ADMIN: &str = "idp.tenant.admin";
/// System management permission code (scope = root tenant only). Includes managing the root tenant
/// itself, and implies every permission code (ADR-0009 §4).
pub const SYSTEM_ADMIN: &str = "idp.system.admin";

/// Action suffix for read operations (`read` in `idp.users:read`).
pub const ACTION_READ: &str = "read";
/// Action suffix for write operations (`write` in `idp.users:write`). Implies `:read`.
pub const ACTION_WRITE: &str = "write";

pub const USERS_READ: &str = "idp.users:read";
pub const USERS_WRITE: &str = "idp.users:write";
pub const APPLICATIONS_READ: &str = "idp.applications:read";
pub const APPLICATIONS_WRITE: &str = "idp.applications:write";
pub const CLIENTS_READ: &str = "idp.clients:read";
pub const CLIENTS_WRITE: &str = "idp.clients:write";
pub const MEMBERS_READ: &str = "idp.members:read";
pub const MEMBERS_WRITE: &str = "idp.members:write";
pub const PERMISSIONS_READ: &str = "idp.permissions:read";
pub const PERMISSIONS_WRITE: &str = "idp.permissions:write";
pub const AUDIT_READ: &str = "idp.audit:read";
pub const KEYS_READ: &str = "idp.keys:read";
pub const KEYS_WRITE: &str = "idp.keys:write";
pub const TENANT_SETTINGS_READ: &str = "idp.tenant-settings:read";
pub const TENANT_SETTINGS_WRITE: &str = "idp.tenant-settings:write";
pub const AUTHENTICATION_POLICIES_READ: &str = "idp.authentication-policies:read";
pub const AUTHENTICATION_POLICIES_WRITE: &str = "idp.authentication-policies:write";
pub const EXTERNAL_IDPS_READ: &str = "idp.external-idps:read";
pub const EXTERNAL_IDPS_WRITE: &str = "idp.external-idps:write";
pub const SAML_SERVICE_PROVIDERS_READ: &str = "idp.saml-service-providers:read";
pub const SAML_SERVICE_PROVIDERS_WRITE: &str = "idp.saml-service-providers:write";
pub const RESOURCES_READ: &str = "idp.resources:read";
pub const RESOURCES_WRITE: &str = "idp.resources:write";
/// Manage admin accounts (task #579).
///
/// With fine-grained codes alone, **accounts holding permissions the caller does not imply** (admin
/// accounts) cannot be managed, and codes the caller does not imply cannot be granted or revoked
/// ([`may_assign`] / [`may_manage_account`]). This code grants that range by name: operating on
/// accounts up to `idp.tenant.admin`, and granting / revoking up to `idp.tenant.admin`. ⚠ It does
/// not reach accounts holding `idp.system.admin` or granting it. It can also be given to clients
/// (so the break-glass machine can recreate emergency accounts).
pub const ADMINS_WRITE: &str = "idp.admins:write";
/// Read the organization's list of SSH public keys (task #885; ADR-0072). A code for the
/// distributing machine (`host-sshkeys`).
///
/// Implied by `idp.tenant.admin` (tenant admins can give it to clients), but ⚠ the endpoint
/// (`GET /{tenant}/admin/ssh-keys`) **only accepts client tokens**. A human's admin token cannot
/// read it even if it implies this code.
pub const SSH_KEYS_READ: &str = "idp.ssh-keys:read";
/// Read mail sending (SMTP) settings. Reads the mail route of the scope's tenant (and the global
/// route if scoped to root).
///
/// ⚠ ADR-0051 §3 said "only holdable in the root scope", but ADR-0058 §8 overturned it. The reason
/// given, "`system_settings` is a global table without a tenant column, so granting it within a
/// tenant would let every tenant's route be changed", disappeared with per-tenant routes
/// (`tenant_settings`). Held in a tenant's scope it reaches **only that tenant's route**, and the
/// global route's endpoint keeps requiring root on the using side.
pub const SMTP_READ: &str = "idp.smtp:read";
/// Change mail sending (SMTP) settings. Same range as [`SMTP_READ`].
pub const SMTP_WRITE: &str = "idp.smtp:write";

/// The set of fine-grained codes implied by `idp.tenant.admin` (ADR-0037).
///
/// **System management operations (creating / deleting tenants, system settings, restart,
/// cross-tenant log viewing) are not included here.** Those still pass only on an exact match of
/// `idp.system.admin`. The purpose of fine-graining is "to divide operations within a tenant", not
/// to sell off root's authority piece by piece.
pub const TENANT_MANAGEMENT_CODES: &[&str] = &[
    USERS_READ,
    USERS_WRITE,
    APPLICATIONS_READ,
    APPLICATIONS_WRITE,
    CLIENTS_READ,
    CLIENTS_WRITE,
    MEMBERS_READ,
    MEMBERS_WRITE,
    PERMISSIONS_READ,
    PERMISSIONS_WRITE,
    AUDIT_READ,
    KEYS_READ,
    KEYS_WRITE,
    TENANT_SETTINGS_READ,
    TENANT_SETTINGS_WRITE,
    AUTHENTICATION_POLICIES_READ,
    AUTHENTICATION_POLICIES_WRITE,
    EXTERNAL_IDPS_READ,
    EXTERNAL_IDPS_WRITE,
    SAML_SERVICE_PROVIDERS_READ,
    SAML_SERVICE_PROVIDERS_WRITE,
    RESOURCES_READ,
    RESOURCES_WRITE,
    ADMINS_WRITE,
    SSH_KEYS_READ,
];

/// Codes that only make sense inside the root tenant (they handle resources shared by all tenants).
///
/// There is one set of signing keys for all tenants (`signing_keys` has no tenant column;
/// ADR-0009), so if a child tenant's admin held it they could **recreate or delete the global keys
/// across tenants**. It stays in the implication of `idp.tenant.admin` (root admins can handle it
/// as before), but outside root it is neither grantable nor usable (the endpoint requires root on
/// the using side, the same shape as SMTP's global route).
pub const ROOT_SCOPED_CODES: &[&str] = &[KEYS_READ, KEYS_WRITE];

/// Whether `code` is in [`ROOT_SCOPED_CODES`].
pub fn is_root_scoped(code: &str) -> bool {
    ROOT_SCOPED_CODES.contains(&code)
}

/// Whether held code `held` satisfies required code `required` (implication; ADR-0037).
///
/// 1. Exact match
/// 2. `idp.system.admin` implies everything (it can only exist in the root scope)
/// 3. `idp.tenant.admin` implies [`TENANT_MANAGEMENT_CODES`]
/// 4. `:write` of the same resource implies `:read`
///
/// The crux of this function is that `idp.tenant.admin` does not imply `idp.system.admin`. Writing
/// implication as "a higher code passes anything" would let tenant admins reach root operations.
pub fn implies(held: &str, required: &str) -> bool {
    if held == required {
        return true;
    }
    if held == SYSTEM_ADMIN {
        return true;
    }
    if held == TENANT_ADMIN {
        return TENANT_MANAGEMENT_CODES.contains(&required);
    }
    // :write → :read of the same resource. `split_once` splits at the first `:`, not "the last one"
    // (assuming resource names contain no `:`; the master is seeded that way too).
    match (held.split_once(':'), required.split_once(':')) {
        (Some((held_resource, ACTION_WRITE)), Some((required_resource, ACTION_READ))) => {
            held_resource == required_resource
        }
        _ => false,
    }
}

/// Whether any code in the held set satisfies the required code (set version of [`implies`]).
pub fn satisfies<S: AsRef<str>>(held: &[S], required: &str) -> bool {
    held.iter().any(|code| implies(code.as_ref(), required))
}

/// Whether the caller, with held codes `held`, may grant / revoke `code` (task #579, ADR-0037).
///
/// Keeps on the granting side the promise that collecting fine-grained codes never reaches admin.
/// Allowed if either:
///
/// 1. The caller implies `code` (handing out a range it holds itself)
/// 2. The caller holds [`ADMINS_WRITE`] and `code` fits within the range of `idp.tenant.admin`
///
/// ⚠ This alone does not make "may grant". The granting endpoint itself (`idp.permissions:write` /
/// `idp.clients:write`), the handling of `idp.system.admin`, and the tenant range
/// ([`is_grantable_in_tenant`]) are checked separately.
///
/// 3. In non-root tenants, tenant admins can also hand out that tenant's mail route permissions
///    (`idp.smtp:*`). `idp.tenant.admin` does not imply SMTP so that it cannot reach the global
///    route in root (ADR-0051); in child tenants what it reaches is only that tenant's route
///    (ADR-0058 §8).
pub fn may_assign<S: AsRef<str>>(held: &[S], code: &str, tenant_is_root: bool) -> bool {
    satisfies(held, code)
        || (satisfies(held, ADMINS_WRITE) && implies(TENANT_ADMIN, code))
        || (!tenant_is_root
            && (code == SMTP_READ || code == SMTP_WRITE)
            && satisfies(held, TENANT_ADMIN))
}

/// Where the scope of a [`HeldByTarget`] permission is, as seen from the requested tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetScope {
    /// The requested tenant (including root).
    RequestedTenant,
    /// The root tenant (the requested tenant is not root).
    RootTenant,
    /// A child tenant that is neither of the above.
    OtherTenant,
}

/// One permission held by the target of an account operation (reissuing password / MFA, changing
/// profile / login identifiers, suspending / deleting).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldByTarget {
    pub code: String,
    pub scope: TargetScope,
}

/// Whether the caller, with held codes `held` (in the requested tenant's scope), may operate on an
/// account holding the permissions in `target` (task #579).
///
/// Being able to operate on an account means being able to use its permissions (reset the password
/// and impersonate). So it is allowed **only when the caller could grant all of the target's
/// permissions**:
///
/// - Permissions in the requested tenant are checked with [`may_assign`] (implied by the caller, or
///   within [`ADMINS_WRITE`])
/// - Permissions in other child tenants (held as a guest) cannot be implied in the requested
///   tenant's scope, so only the range of [`ADMINS_WRITE`] (up to `idp.tenant.admin`) is allowed
/// - Root permissions (held as a guest) are not allowed. A child tenant's admin would reach root
///   administration (ADR-0070; accounts administering root have root as their home)
/// - Holders of `idp.system.admin` can only be handled by holders of `idp.system.admin`
pub fn may_manage_account<S: AsRef<str>>(
    held: &[S],
    target: &[HeldByTarget],
    tenant_is_root: bool,
) -> bool {
    target.iter().all(|t| {
        if t.code == SYSTEM_ADMIN {
            satisfies(held, SYSTEM_ADMIN)
        } else {
            match t.scope {
                TargetScope::RequestedTenant => may_assign(held, &t.code, tenant_is_root),
                TargetScope::RootTenant => false,
                TargetScope::OtherTenant => {
                    satisfies(held, ADMINS_WRITE) && implies(TENANT_ADMIN, &t.code)
                }
            }
        }
    })
}

/// Whether a code may be granted to a client (system client) (ADR-0037).
///
/// Comprehensive admin permissions (`idp.system.admin` / `idp.tenant.admin`) cannot be granted.
/// Machine credentials live longer than human ones and have weaker revocation paths, so "just
/// attach the higher code" is blocked to force choosing fine-grained codes. The DB has the same
/// CHECK constraint, so the check works twice.
pub fn is_grantable_to_client(code: &str) -> bool {
    code != SYSTEM_ADMIN && code != TENANT_ADMIN
}

/// Whether the code **can be granted at all** in the requested tenant (ADR-0009 §4).
///
/// `idp.system.admin` can only exist in the root scope (double defense by the DB CHECK constraint
/// `user_permissions_system_admin_scope_chk` and the app layer). So in non-root tenants it cannot
/// be granted by anyone. **Do not show what cannot be chosen** (ADR-0032), so the grant form's
/// options are filtered by this check. Otherwise options that always end in 403 would remain.
///
/// ⚠ `idp.smtp:*` became grantable within tenants by ADR-0058 §8 (it only reaches that tenant's
/// route). ⚠ [`ROOT_SCOPED_CODES`] (signing keys) are also grantable only within root (resources
/// shared by all tenants).
pub fn is_grantable_in_tenant(code: &str, tenant_is_root: bool) -> bool {
    tenant_is_root || (code != SYSTEM_ADMIN && !is_root_scoped(code))
}

/// Namespaced permission code (e.g. `idp.tenant.admin`, `idp.clients:read`).
///
/// The single source of allowed values is the `permissions` master table (seed migrations);
/// this type guarantees only the minimal invariant "non-empty string". Existence is checked by
/// the repository (`UserPermissionRepository`) and FK constraints.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PermissionCode(String);

impl PermissionCode {
    /// Builds a permission code from a string. Empty strings are rejected.
    pub fn parse(s: impl Into<String>) -> Result<Self, DomainError> {
        let s = s.into();
        if s.trim().is_empty() {
            return Err(DomainError::InvalidValue(
                "permission code must not be empty".to_string(),
            ));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PermissionCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_non_empty_code() {
        let code = PermissionCode::parse("idp.tenant.admin").unwrap();
        assert_eq!(code.as_str(), "idp.tenant.admin");
        assert_eq!(code.to_string(), "idp.tenant.admin");
    }

    #[test]
    fn rejects_empty_or_blank_code() {
        assert!(PermissionCode::parse("").is_err());
        assert!(PermissionCode::parse("   ").is_err());
    }

    #[test]
    fn exact_match_implies() {
        assert!(implies(USERS_READ, USERS_READ));
        assert!(implies(SYSTEM_ADMIN, SYSTEM_ADMIN));
    }

    #[test]
    fn system_admin_implies_everything() {
        assert!(implies(SYSTEM_ADMIN, TENANT_ADMIN));
        assert!(implies(SYSTEM_ADMIN, USERS_WRITE));
        for code in TENANT_MANAGEMENT_CODES {
            assert!(implies(SYSTEM_ADMIN, code));
        }
    }

    /// Existing holders of `idp.tenant.admin` pass the admin API as before even after
    /// fine-graining.
    #[test]
    fn smtp_codes_are_not_reachable_from_tenant_admin() {
        // ⚠ **Not reachable from tenant admins.** If it were, root's tenant admins would
        //   reach the global mail route (ADR-0051; ADR-0058 §8 did not change this point).
        assert!(!implies(TENANT_ADMIN, SMTP_READ));
        assert!(!implies(TENANT_ADMIN, SMTP_WRITE));
        assert!(!TENANT_MANAGEMENT_CODES.contains(&SMTP_READ));
        assert!(!TENANT_MANAGEMENT_CODES.contains(&SMTP_WRITE));
        // Reachable from system admins (implication rule 2). Write includes read (rule 4).
        assert!(implies(SYSTEM_ADMIN, SMTP_WRITE));
        assert!(implies(SMTP_WRITE, SMTP_READ));
        assert!(!implies(SMTP_READ, SMTP_WRITE));
    }

    /// ADR-0058 §8: each tenant can have its own route, so SMTP codes are grantable in any tenant.
    /// What they reach is only the scope tenant's route; the global route's endpoint requires root
    /// on the using side.
    #[test]
    fn smtp_codes_are_grantable_inside_any_tenant() {
        for code in [SMTP_READ, SMTP_WRITE] {
            assert!(is_grantable_in_tenant(code, true), "{code}");
            assert!(is_grantable_in_tenant(code, false), "{code}");
            // Since it is an endpoint for machines to set it, it can be given to clients too.
            assert!(is_grantable_to_client(code), "{code}");
        }
        // ⚠ Only `idp.system.admin` is still grantable only within root, as before.
        assert!(!is_grantable_in_tenant(SYSTEM_ADMIN, false));
        assert!(is_grantable_in_tenant(SYSTEM_ADMIN, true));
    }

    #[test]
    fn tenant_admin_implies_every_tenant_management_code() {
        for code in TENANT_MANAGEMENT_CODES {
            assert!(implies(TENANT_ADMIN, code), "{code} not implied");
        }
    }

    /// The crux of this module: tenant admins do not reach root operations.
    #[test]
    fn tenant_admin_does_not_imply_system_admin() {
        assert!(!implies(TENANT_ADMIN, SYSTEM_ADMIN));
    }

    #[test]
    fn write_implies_read_of_the_same_resource() {
        assert!(implies(USERS_WRITE, USERS_READ));
        assert!(implies(CLIENTS_WRITE, CLIENTS_READ));
        // It does not extend to other resources.
        assert!(!implies(USERS_WRITE, CLIENTS_READ));
        // The reverse (read → write) is not implied.
        assert!(!implies(USERS_READ, USERS_WRITE));
    }

    #[test]
    fn satisfies_scans_the_held_set() {
        let held = vec![USERS_WRITE.to_string(), AUDIT_READ.to_string()];
        assert!(satisfies(&held, USERS_READ));
        assert!(satisfies(&held, AUDIT_READ));
        assert!(!satisfies(&held, CLIENTS_WRITE));
        assert!(!satisfies::<String>(&[], USERS_READ));
    }

    #[test]
    fn blanket_admin_codes_are_not_grantable_to_clients() {
        assert!(!is_grantable_to_client(SYSTEM_ADMIN));
        assert!(!is_grantable_to_client(TENANT_ADMIN));
        for code in TENANT_MANAGEMENT_CODES {
            assert!(is_grantable_to_client(code));
        }
    }

    #[test]
    fn system_admin_is_not_grantable_outside_the_root_tenant() {
        // In non-root, the CHECK constraint refuses the row's very existence, so it must not appear
        // as an option.
        assert!(!is_grantable_in_tenant(SYSTEM_ADMIN, false));
        assert!(is_grantable_in_tenant(SYSTEM_ADMIN, true));
    }

    #[test]
    fn every_other_code_is_grantable_in_any_tenant() {
        assert!(is_grantable_in_tenant(TENANT_ADMIN, false));
        assert!(is_grantable_in_tenant(TENANT_ADMIN, true));
        for code in TENANT_MANAGEMENT_CODES {
            if is_root_scoped(code) {
                continue;
            }
            assert!(is_grantable_in_tenant(code, false));
            assert!(is_grantable_in_tenant(code, true));
        }
    }

    /// Signing keys are shared by all tenants, so they are not grantable in child tenants (only
    /// within root).
    #[test]
    fn signing_key_codes_are_grantable_only_in_the_root_tenant() {
        for code in [KEYS_READ, KEYS_WRITE] {
            assert!(is_root_scoped(code), "{code}");
            assert!(!is_grantable_in_tenant(code, false), "{code}");
            assert!(is_grantable_in_tenant(code, true), "{code}");
        }
        // Root admins hold it via implication as before.
        assert!(implies(TENANT_ADMIN, KEYS_WRITE));
        assert!(!is_root_scoped(USERS_WRITE));
    }

    fn here(code: &str) -> HeldByTarget {
        HeldByTarget {
            code: code.to_string(),
            scope: TargetScope::RequestedTenant,
        }
    }

    fn elsewhere(code: &str) -> HeldByTarget {
        HeldByTarget {
            code: code.to_string(),
            scope: TargetScope::OtherTenant,
        }
    }

    fn in_root(code: &str) -> HeldByTarget {
        HeldByTarget {
            code: code.to_string(),
            scope: TargetScope::RootTenant,
        }
    }

    /// Fine-grained codes cannot hand out codes they do not imply (task #579 (b)(c)).
    #[test]
    fn fine_grained_holders_cannot_assign_what_they_do_not_hold() {
        let permissions_writer = [PERMISSIONS_WRITE];
        assert!(!may_assign(&permissions_writer, TENANT_ADMIN, true));
        assert!(!may_assign(&permissions_writer, SMTP_WRITE, true));
        assert!(!may_assign(&permissions_writer, USERS_WRITE, true));
        assert!(may_assign(&permissions_writer, PERMISSIONS_READ, true));
        let clients_writer = [CLIENTS_WRITE];
        assert!(!may_assign(&clients_writer, USERS_WRITE, true));
        assert!(may_assign(&clients_writer, CLIENTS_READ, true));
        // Tenant admins can hand out all permissions within the tenant as before. ⚠ system.admin
        // and SMTP are separate.
        assert!(may_assign(&[TENANT_ADMIN], TENANT_ADMIN, true));
        assert!(may_assign(&[TENANT_ADMIN], USERS_WRITE, true));
        assert!(may_assign(&[TENANT_ADMIN], ADMINS_WRITE, true));
        assert!(!may_assign(&[TENANT_ADMIN], SYSTEM_ADMIN, true));
        assert!(!may_assign(&[TENANT_ADMIN], SMTP_WRITE, true));
    }

    /// In child tenants, tenant admins can also hand out that tenant's mail route permissions
    /// (ADR-0058 §8). Not in root (it would reach the global route; ADR-0051).
    #[test]
    fn tenant_admin_assigns_smtp_codes_only_outside_the_root_tenant() {
        assert!(may_assign(&[TENANT_ADMIN], SMTP_WRITE, false));
        assert!(may_assign(&[TENANT_ADMIN], SMTP_READ, false));
        assert!(!may_assign(&[TENANT_ADMIN], SMTP_WRITE, true));
        assert!(!may_assign(&[PERMISSIONS_WRITE], SMTP_WRITE, false));
    }

    /// `idp.admins:write` grants by name the range up to idp.tenant.admin (the break-glass
    /// machine).
    #[test]
    fn admins_write_reaches_tenant_admin_but_not_system_admin() {
        let breakglass = [USERS_WRITE, PERMISSIONS_WRITE, ADMINS_WRITE];
        assert!(may_assign(&breakglass, TENANT_ADMIN, true));
        assert!(may_assign(&breakglass, KEYS_WRITE, true));
        assert!(!may_assign(&breakglass, SYSTEM_ADMIN, true));
        assert!(!may_assign(&breakglass, SMTP_WRITE, true));
        assert!(is_grantable_to_client(ADMINS_WRITE));
        assert!(implies(TENANT_ADMIN, ADMINS_WRITE));
        assert!(!implies(ADMINS_WRITE, USERS_WRITE));
    }

    /// `idp.users:write` alone cannot handle admin accounts (task #579 (a)).
    #[test]
    fn users_writer_cannot_manage_an_administrator() {
        let users_writer = [USERS_WRITE];
        assert!(may_manage_account(&users_writer, &[], true));
        assert!(may_manage_account(&users_writer, &[here(USERS_READ)], true));
        assert!(!may_manage_account(
            &users_writer,
            &[here(TENANT_ADMIN)],
            true
        ));
        assert!(!may_manage_account(
            &users_writer,
            &[here(SMTP_WRITE)],
            true
        ));
        assert!(!may_manage_account(
            &users_writer,
            &[here(PERMISSIONS_WRITE)],
            true
        ));
        // Permissions held as a guest in other tenants are protected too.
        assert!(!may_manage_account(
            &users_writer,
            &[elsewhere(USERS_READ)],
            true
        ));
    }

    #[test]
    fn tenant_admin_and_admins_write_manage_administrators_but_not_system_admins() {
        for held in [&[TENANT_ADMIN][..], &[USERS_WRITE, ADMINS_WRITE][..]] {
            assert!(
                may_manage_account(held, &[here(TENANT_ADMIN)], true),
                "{held:?}"
            );
            assert!(
                may_manage_account(held, &[elsewhere(TENANT_ADMIN)], true),
                "{held:?}"
            );
            assert!(
                !may_manage_account(held, &[here(TENANT_ADMIN), here(SYSTEM_ADMIN)], true),
                "{held:?}"
            );
            assert!(
                !may_manage_account(held, &[elsewhere(SMTP_WRITE)], true),
                "{held:?}"
            );
        }
        assert!(may_manage_account(
            &[SYSTEM_ADMIN],
            &[here(SYSTEM_ADMIN), here(TENANT_ADMIN)],
            true
        ));
    }

    /// A child tenant's admin cannot handle the accounts of root's guest admins (task #757,
    /// ADR-0070). ⚠ Guests from other child tenants are as before (their home tenant's admin
    /// governs the account; ADR-0009 §3).
    #[test]
    fn a_child_tenant_cannot_manage_a_guest_administrator_of_the_root() {
        for held in [&[TENANT_ADMIN][..], &[USERS_WRITE, ADMINS_WRITE][..]] {
            for code in [TENANT_ADMIN, KEYS_WRITE, USERS_READ] {
                assert!(
                    !may_manage_account(held, &[here(USERS_READ), in_root(code)], false),
                    "{held:?} {code}"
                );
            }
            assert!(
                may_manage_account(held, &[here(USERS_READ), elsewhere(TENANT_ADMIN)], false),
                "{held:?}"
            );
        }
    }

    /// Tenant setting permissions do not reach global settings (ADR-0058 §11; defense on the
    /// granting side). The global settings endpoint passes only on an exact match of
    /// `idp.system.admin`, and the SMTP endpoint is a separate one.
    #[test]
    fn tenant_settings_codes_do_not_reach_the_whole_idp_settings() {
        for held in [TENANT_SETTINGS_READ, TENANT_SETTINGS_WRITE] {
            for whole in [SYSTEM_ADMIN, SMTP_READ, SMTP_WRITE, TENANT_ADMIN] {
                assert!(!implies(held, whole), "{held} must not imply {whole}");
            }
        }
        assert!(implies(TENANT_SETTINGS_WRITE, TENANT_SETTINGS_READ));
        assert!(!implies(TENANT_SETTINGS_READ, TENANT_SETTINGS_WRITE));
    }
}
