//! Authentication policies (user authentication & authentication policy spec §7-§9).
//!
//! An authentication policy is a rule deciding "conditions to be met at authentication (deny, MFA required)",
//! kept separate from identity verification (authenticators such as password and TOTP) (same spec §2.3). Satisfying a policy
//! does not make authentication succeed unless identity verification succeeded. Evaluation is a pure function ([`evaluate_policies`]),
//! independent of the DB and frameworks.
#![allow(dead_code)]

use crate::domain::error::DomainError;
use crate::domain::tenant::TenantId;
use crate::domain::values::{AuthenticationMethod, ACR_MULTI_FACTOR};
use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// Effect of a policy (spec §7.4).
///
/// `require_additional_authentication` is a request to "add one second factor", so it is `RequireMfa`;
/// a request "do not pass unless this method" is expressed as `RequireSpecificMethod` (including §12.2's WebAuthn required
/// and UV required). They are separate because the former accepts **any**, while
/// the latter **specifies the method**; merging them into one would create holes like "having TOTP registered slips past
/// WebAuthn required".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEffect {
    /// Allows authentication when the conditions are met.
    Allow,
    /// Denies authentication when the conditions are met (deny always takes precedence over allow. Spec §9.3).
    Deny,
    /// Requires MFA (additional authentication) when the conditions are met. Any method.
    RequireMfa,
    /// Requires **a specific authentication method** when the conditions are met (AP3. Parameters are in
    /// [`AuthenticationPolicy::effect_params`]).
    RequireSpecificMethod,
}

impl PolicyEffect {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireMfa => "require_mfa",
            Self::RequireSpecificMethod => "require_specific_method",
        }
    }

    /// Restores from the DB stored value (`VARCHAR` + CHECK constraint). This enum is the single source of allowed values.
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            "require_mfa" => Ok(Self::RequireMfa),
            "require_specific_method" => Ok(Self::RequireSpecificMethod),
            other => Err(DomainError::InvalidValue(format!(
                "unknown policy effect: {other}"
            ))),
        }
    }
}

/// The requirement of `require_specific_method` (spec §12.2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredMethods {
    /// Allowed authentication methods. Satisfied if **any one** was actually used (OR).
    /// Empty = no method specified (used when requiring only `user_verification`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<AuthenticationMethod>,
    /// Whether WebAuthn User Verification (user confirmation by biometrics/PIN) is required.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub user_verification: bool,
}

impl RequiredMethods {
    /// Whether the authentication methods actually used (and whether UV was done) satisfy the requirement.
    ///
    /// `methods` is OR. To express an AND like "both password and webauthn",
    /// split into 2 policies (bringing an implicit AND into one condition makes reading it on the admin screen
    /// and explaining it in the audit harder).
    pub fn satisfied_by(&self, used: &[AuthenticationMethod], user_verified: bool) -> bool {
        let method_ok = self.methods.is_empty() || used.iter().any(|m| self.methods.contains(m));
        let uv_ok = !self.user_verification || user_verified;
        method_ok && uv_ok
    }

    /// Renders the requirement in human-readable form (for audit logs. Operating language = English).
    pub fn describe(&self) -> String {
        let methods: Vec<&str> = self.methods.iter().map(|m| m.as_str()).collect();
        match (methods.is_empty(), self.user_verification) {
            (true, true) => "user_verification".to_string(),
            (true, false) => "(none)".to_string(),
            (false, true) => format!("{}+user_verification", methods.join("|")),
            (false, false) => methods.join("|"),
        }
    }
}

/// An applicable time window expressed by weekday and time (spec §8 "time window").
///
/// The time zone is expressed as a **fixed offset (minutes)**. IANA time zone names are not accepted because
/// handling DST transitions correctly requires bundling and keeping the tz database updated,
/// taking on the new operational risk that "neglecting those updates silently shifts authentication policies".
/// With a fixed offset the decision is always deterministic, and regions with DST can be expressed with 2 policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeWindow {
    /// Target weekdays (0 = Sunday ... 6 = Saturday). Empty = all days.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub days: Vec<u8>,
    /// Start time (minutes since 00:00 of the day. 0-1439).
    pub start_minute: u16,
    /// End time (same as above. If smaller than `start_minute`, treated as a window **crossing midnight**).
    pub end_minute: u16,
    /// UTC offset used for the decision (minutes. e.g. JST = 540).
    #[serde(default)]
    pub utc_offset_minutes: i16,
}

impl TimeWindow {
    /// Validates the value range (admin API input validation. Do not put broken windows into the DB).
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.start_minute > 1439 || self.end_minute > 1439 {
            return Err(DomainError::InvalidValue(
                "time window minutes must be 0-1439".to_string(),
            ));
        }
        if self.days.iter().any(|d| *d > 6) {
            return Err(DomainError::InvalidValue(
                "time window days must be 0 (Sunday) - 6 (Saturday)".to_string(),
            ));
        }
        if self.utc_offset_minutes < -840 || self.utc_offset_minutes > 840 {
            return Err(DomainError::InvalidValue(
                "time window UTC offset must be within +/-14:00".to_string(),
            ));
        }
        Ok(())
    }

    /// Whether `now` falls within this window.
    pub fn contains(&self, now: DateTime<Utc>) -> bool {
        let local = now + chrono::Duration::minutes(self.utc_offset_minutes as i64);
        let minute = (local.hour() * 60 + local.minute()) as u16;
        // A window crossing midnight (e.g. 22:00-06:00) checks the weekday on the start-day side. Unless the early morning
        // after crossing is treated as "the previous day's window", a window starting at 22:00 would end at 00:00.
        let (in_range, day) = if self.start_minute <= self.end_minute {
            (
                minute >= self.start_minute && minute < self.end_minute,
                local.weekday().num_days_from_sunday() as u8,
            )
        } else if minute >= self.start_minute {
            (true, local.weekday().num_days_from_sunday() as u8)
        } else if minute < self.end_minute {
            // Continuation of the previous day's window.
            (true, (local.weekday().num_days_from_sunday() as u8 + 6) % 7)
        } else {
            (false, 0)
        };
        in_range && (self.days.is_empty() || self.days.contains(&day))
    }
}

/// Conditions under which a policy applies (spec §8. Stored in a JSON column).
///
/// Each condition is **empty = no restriction (matches everything)**; non-empty = holds if any matches. Multiple conditions are AND.
/// Conditions evaluable before identifying the user (`application_ids`) and conditions evaluable only after identifying the user
/// (`user_ids`) are mixed, so evaluation happens after identifying the user (spec §9.1).
///
/// **Conditions without evaluation inputs fall to "no match".** For example, a policy with `ip_cidrs` does not match
/// requests where the source IP cannot be obtained (internal paths with `TRUST_FORWARDED_HEADERS=false`, etc.).
/// For `deny` policies this misses some, but conversely "treat as a match because there is no input" would
/// make `allow` policies spread unconditionally. If one must choose, a consistent rule that **a condition holds only when
/// explicitly satisfied** is harder to misread.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConditions {
    /// Target apps (`applications.id`). Empty = all apps.
    ///
    /// ⚠ **Points to apps, not clients** (ADR-0054 decision 5). With `client_ids`,
    /// SAML apps would remain outside policies and MFA could not be required. Not taking the approach of listing
    /// `service_provider_ids` because conditions would grow every time a protocol is added.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub application_ids: Vec<Uuid>,
    /// Target users (internal user IDs). Empty = all users.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_ids: Vec<Uuid>,
    /// Target network zones (CIDR notation. IPv4 / IPv6). Empty = all networks (AP3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_cidrs: Vec<String>,
    /// Target time windows. Empty = always. Multiple entries hold if any contains it (OR. AP3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub time_windows: Vec<TimeWindow>,
    /// Values contained in the authorization request's `acr_values`. Empty = regardless of the request (AP3, G12).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_acr: Vec<String>,
}

impl PolicyConditions {
    /// Validates the format (admin API input validation).
    pub fn validate(&self) -> Result<(), DomainError> {
        for cidr in &self.ip_cidrs {
            IpRange::parse(cidr)?;
        }
        for window in &self.time_windows {
            window.validate()?;
        }
        Ok(())
    }

    /// Whether it matches the authentication context (empty conditions always match).
    pub fn matches(&self, ctx: &AuthenticationContext) -> bool {
        // In contexts where the app cannot be resolved (portal, admin console, clients without a binding yet),
        // policies with `application_ids` do not match, per this module's rule that conditions without
        // evaluation inputs fall to "no match".
        let application_ok = self.application_ids.is_empty()
            || ctx
                .application_id
                .is_some_and(|id| self.application_ids.contains(&id));
        let user_ok = self.user_ids.is_empty() || self.user_ids.contains(&ctx.user_id);
        let network_ok = self.ip_cidrs.is_empty() || self.matches_network(ctx.ip_address);
        let time_ok =
            self.time_windows.is_empty() || self.time_windows.iter().any(|w| w.contains(ctx.now));
        let acr_ok = self.requested_acr.is_empty()
            || ctx
                .requested_acr
                .iter()
                .any(|requested| self.requested_acr.iter().any(|v| v == requested));
        application_ok && user_ok && network_ok && time_ok && acr_ok
    }

    fn matches_network(&self, ip_address: Option<&str>) -> bool {
        let Some(ip) = ip_address.and_then(|raw| raw.parse::<IpAddr>().ok()) else {
            // For requests whose source is unknown, policies with network conditions do not match.
            return false;
        };
        self.ip_cidrs
            .iter()
            .filter_map(|cidr| IpRange::parse(cidr).ok())
            .any(|range| range.contains(ip))
    }
}

/// An address range in CIDR notation (`192.0.2.0/24`, `2001:db8::/32`. A single address when the prefix is omitted).
///
/// Decided using only the `IpAddr` bytes and the prefix length, so no external crate is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRange {
    network: IpAddr,
    prefix_len: u8,
}

impl IpRange {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let invalid = || DomainError::InvalidValue(format!("invalid CIDR or IP address: {value}"));
        let (addr_part, prefix_part) = match value.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (value, None),
        };
        let network: IpAddr = addr_part.parse().map_err(|_| invalid())?;
        let max_len = if network.is_ipv4() { 32 } else { 128 };
        let prefix_len = match prefix_part {
            Some(p) => p.parse::<u8>().map_err(|_| invalid())?,
            None => max_len,
        };
        if prefix_len > max_len {
            return Err(invalid());
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                prefix_matches(&net.octets(), &addr.octets(), self.prefix_len)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                prefix_matches(&net.octets(), &addr.octets(), self.prefix_len)
            }
            // Do not compare across IPv4 and IPv6 (implicitly equating IPv4-mapped IPv6 would create gaps
            // like "accessing via IPv6 escapes IPv4 deny ranges").
            _ => false,
        }
    }
}

/// Whether the leading `prefix_len` bits match.
fn prefix_matches(network: &[u8], addr: &[u8], prefix_len: u8) -> bool {
    let full_bytes = (prefix_len / 8) as usize;
    if network[..full_bytes] != addr[..full_bytes] {
        return false;
    }
    let remaining_bits = prefix_len % 8;
    if remaining_bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - remaining_bits);
    network[full_bytes] & mask == addr[full_bytes] & mask
}

/// Input to policy evaluation (the authentication context. Information as of spec §9.1 "after identifying the user").
#[derive(Debug, Clone, Copy)]
pub struct AuthenticationContext<'a> {
    /// The flow's app (ADR-0054). `None` for app-independent paths such as portal sign-in, and for clients
    /// not yet connected to an app.
    pub application_id: Option<Uuid>,
    /// Internal ID of the identified user.
    pub user_id: Uuid,
    /// Source IP (the value that passed the `TRUST_FORWARDED_HEADERS` check. `None` if unavailable).
    pub ip_address: Option<&'a str>,
    /// Evaluation time (used for time window conditions).
    pub now: DateTime<Utc>,
    /// The authorization request's `acr_values` (empty on non-OIDC paths).
    pub requested_acr: &'a [String],
}

impl<'a> AuthenticationContext<'a> {
    /// The minimal context with no app, network, time or acr (portal / admin console, etc.).
    pub fn for_user(user_id: Uuid, now: DateTime<Utc>) -> Self {
        Self {
            application_id: None,
            user_id,
            ip_address: None,
            now,
            requested_acr: &[],
        }
    }
}

/// One authentication policy (`authentication_policies` table. A subset of spec §7.3).
#[derive(Debug, Clone)]
pub struct AuthenticationPolicy {
    pub id: Uuid,
    /// Policies are managed per tenant (not applied across tenants).
    pub tenant_id: TenantId,
    /// Identifier code unique within the tenant (e.g. `deny-legacy-client`).
    pub policy_code: String,
    pub policy_name: String,
    /// Evaluation order (ascending = smaller has priority. Spec §9.2).
    pub priority: i32,
    pub enabled: bool,
    pub effect: PolicyEffect,
    /// The requirement of `require_specific_method` (`None` for other effects).
    pub effect_params: Option<RequiredMethods>,
    pub conditions: PolicyConditions,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AuthenticationPolicy {
    /// Format validation of `policy_code` (alphanumerics, `-`, `_`, `.`, 1-100 chars).
    /// Limited to characters safe to put as-is into URL path segments and audit logs.
    pub fn validate_code(code: &str) -> Result<(), DomainError> {
        if code.is_empty() || code.len() > 100 {
            return Err(DomainError::InvalidValue(
                "policy code must be 1-100 characters".to_string(),
            ));
        }
        if !code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        {
            return Err(DomainError::InvalidValue(
                "policy code must contain only ASCII alphanumerics, '-', '_' or '.'".to_string(),
            ));
        }
        Ok(())
    }

    /// Validates the consistency of effect and parameters.
    ///
    /// `require_specific_method` is meaningless without "what to require" (a policy requiring nothing
    /// would line up looking like `allow`). Conversely, having parameters with other effects would leave dead settings
    /// when switching effects on the admin screen.
    pub fn validate_effect_params(
        effect: PolicyEffect,
        params: Option<&RequiredMethods>,
    ) -> Result<(), DomainError> {
        match (effect, params) {
            (PolicyEffect::RequireSpecificMethod, Some(p))
                if !p.methods.is_empty() || p.user_verification =>
            {
                Ok(())
            }
            (PolicyEffect::RequireSpecificMethod, _) => Err(DomainError::InvalidValue(
                "require_specific_method needs at least one method or user_verification"
                    .to_string(),
            )),
            (_, Some(_)) => Err(DomainError::InvalidValue(
                "effect parameters are only valid for require_specific_method".to_string(),
            )),
            (_, None) => Ok(()),
        }
    }

    /// Validation of `policy_name` (non-empty, at most 200 chars).
    pub fn validate_name(name: &str) -> Result<(), DomainError> {
        if name.trim().is_empty() || name.chars().count() > 200 {
            return Err(DomainError::InvalidValue(
                "policy name must be 1-200 characters".to_string(),
            ));
        }
        Ok(())
    }
}

/// Conclusion of policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Authentication may continue (`matched_policy_code` = the matching allow policy. `None` for the default allow).
    Allow { matched_policy_code: Option<String> },
    /// Deny authentication (spec §9.3: deny takes precedence over everything else).
    Deny { policy_code: String },
    /// Authentication does not succeed until MFA (additional authentication) is completed.
    RequireMfa { policy_code: String },
    /// Authentication does not succeed unless authenticated with the specified method (AP3. Spec §12.2).
    ///
    /// **Holds all matching method-specifying policies.** Taking only the first would break the
    /// `RequiredMethods` convention "AND is expressed by splitting into 2 policies" (satisfying just the higher-priority one
    /// would let the other's requirement be ignored). All requirements must be satisfied.
    RequireMethods {
        requirements: Vec<MethodRequirement>,
    },
}

/// One matching method-specifying policy (carries the code, to record in the audit which policy required it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodRequirement {
    pub policy_code: String,
    pub requirement: RequiredMethods,
}

impl PolicyDecision {
    /// Returns the first `require_specific_method` (AP3) requirement that is **not satisfied**.
    ///
    /// `None` when satisfied or when it is not a method specification at all. The decision is placed here because
    /// there are 7 sign-in paths (OIDC password / MFA / passkey / external IdP / forced password change /
    /// portal / admin console), and writing it in each would make the rules drift.
    ///
    /// **All** matching requirements are checked (looking only at the first breaks the AND expression).
    pub fn unmet_method_requirement(
        &self,
        used: &[AuthenticationMethod],
        user_verified: bool,
    ) -> Option<&MethodRequirement> {
        match self {
            Self::RequireMethods { requirements } => requirements
                .iter()
                .find(|m| !m.requirement.satisfied_by(used, user_verified)),
            _ => None,
        }
    }

    /// "Can it be satisfied by adding one second factor". Used to decide whether to lead to the MFA step.
    ///
    /// This gives method specifications the same treatment `require_mfa` has: "send users with authenticators
    /// to the MFA step and deny only those without". Leading there does not let anyone through with an unsatisfiable second factor,
    /// because the decision against the final set of methods is redone on MFA completion.
    pub fn satisfied_by_adding(
        &self,
        used: &[AuthenticationMethod],
        candidate: AuthenticationMethod,
        user_verified: bool,
    ) -> bool {
        let mut with_candidate = used.to_vec();
        with_candidate.push(candidate);
        self.unmet_method_requirement(&with_candidate, user_verified)
            .is_none()
    }
}

/// The policy code used when recording a built-in MFA requirement via a reserved word in the audit (ADR-0043).
///
/// It **appears in the same field** as tenant-defined policies, so it is shaped to make clear that it is a value
/// that cannot be found by searching on the admin screen (`policy=builtin:acr_values`).
pub const BUILTIN_ACR_POLICY_CODE: &str = "builtin:acr_values";

/// Default behavior when no policy matches (spec §9.4 "set explicitly").
///
/// Default is `Allow` (does not change the behavior of existing environments without policies). To switch to default deny,
/// specify `deny` in the setting (`AUTH_POLICY_DEFAULT_EFFECT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultPolicyEffect {
    Allow,
    Deny,
}

impl DefaultPolicyEffect {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            other => Err(DomainError::InvalidValue(format!(
                "unknown default policy effect: {other}"
            ))),
        }
    }
}

/// Account lock policy (spec §17. Allowed failure count, lock duration).
///
/// Consolidates the values formerly hard-coded in each sign-in service (10 times / 15 minutes) into a single value representation
/// injected from settings (`LOGIN_MAX_FAILED_ATTEMPTS` / `LOGIN_LOCK_DURATION_SECS`).
/// Locks are per user (spec §17.2). Permanent locks are avoided (only locks with expiry).
///
/// # Progressive lock (AP6)
///
/// The lock duration grows as failures pile up. With a fixed duration, an attacker can repeat "wait only the lock duration
/// and try up to the threshold again" forever, keeping the attempts per unit time constant. On the other hand, making the first
/// lock long would lock out for a long time users who merely mistyped repeatedly.
/// **Short at first, longer the more it repeats** (doubling from `lock_duration_secs` up to
/// `max_lock_duration_secs`) separates the two.
///
/// The stage is determined using `failed_login_count` as is. This value returns to 0 **only on a successful sign-in**,
/// so the first failure after a lock expires becomes "threshold + 1" and automatically advances to the next stage.
/// Stages can be expressed without an extra state column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutPolicy {
    /// Allowed number of consecutive failures (lock when this count is reached).
    pub max_failed_attempts: i32,
    /// First lock duration (seconds).
    pub lock_duration_secs: u64,
    /// Upper bound of the progressive lock (seconds). If at most `lock_duration_secs`, no progression happens (= fixed duration).
    pub max_lock_duration_secs: u64,
}

/// Max number of progressive lock stages. Extending up to 2^ESCALATION_STEPS times `lock_duration_secs`
/// always reaches the upper bound (default 24 hours), exceeding 32 hours even with the default (15 minutes). The stage count is capped
/// so that the computation stays saturated however large the failure count is.
const ESCALATION_STEPS: u32 = 16;

impl LockoutPolicy {
    /// Returns the lock expiry if it should lock when the failure count reaches `failed_count`.
    pub fn locked_until_after_failure(
        &self,
        failed_count: i32,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        (failed_count >= self.max_failed_attempts).then(|| {
            now + chrono::Duration::seconds(self.lock_duration_secs_for(failed_count) as i64)
        })
    }

    /// The lock duration (seconds) when locking at cumulative failure count `failed_count`.
    ///
    /// `lock_duration_secs` exactly at the threshold, then doubled with each further failure.
    /// Capped at `max_lock_duration_secs`.
    pub fn lock_duration_secs_for(&self, failed_count: i32) -> u64 {
        let over = failed_count.saturating_sub(self.max_failed_attempts).max(0);
        let step = (over as u32).min(ESCALATION_STEPS);
        let scaled = self
            .lock_duration_secs
            .saturating_mul(1u64.checked_shl(step).unwrap_or(u64::MAX));
        scaled
            .min(self.max_lock_duration_secs)
            // Even if the upper bound is set shorter than the first, the first lock duration always applies
            // (so a misconfigured upper bound does not effectively disable locking).
            .max(self.lock_duration_secs)
    }

    /// Enumerates the progressive lock "stages", largest excess over the threshold first (AP6).
    ///
    /// Returns pairs of `(if the failure count is at least this, lock seconds)` in **descending** order.
    /// Recording the failure and the lock decision must be done in one `UPDATE` statement (SEC13. Reading and writing back
    /// would miss concurrent attempts), and the failure count at that moment exists only inside SQL. Copying the lock duration formula
    /// into SQL would duplicate the definition, so **the domain passes the list of stages and the SQL side only chooses**
    /// (`CASE WHEN failed_login_count + 1 >= ? THEN ? ...`).
    ///
    /// Stages beyond the one reaching the upper bound have the same value, so they are not enumerated (the last stage means "everything beyond").
    pub fn escalation_ladder(&self) -> Vec<(i32, u64)> {
        let mut ladder: Vec<(i32, u64)> = Vec::new();
        for step in 0..=ESCALATION_STEPS {
            let threshold = self.max_failed_attempts.saturating_add(step as i32);
            let duration = self.lock_duration_secs_for(threshold);
            // Once the upper bound is reached, later stages have the same value, so stop.
            let capped = duration >= self.max_lock_duration_secs;
            ladder.push((threshold, duration));
            if capped {
                break;
            }
        }
        ladder.reverse();
        ladder
    }
}

/// Whether the RP requested MFA via a reserved word (ADR-0043).
///
/// Unknown strings are ignored, so as not to break the existing use of tenants writing their own strings in
/// `requested_acr` conditions (those still work as conditions).
fn requests_mfa(requested_acr: &[String]) -> bool {
    requested_acr.iter().any(|v| v == ACR_MULTI_FACTOR)
}

/// Evaluates authentication policies (spec §9).
///
/// - Only `enabled` policies whose conditions match are considered.
/// - If even one `Deny` matches, it is **always** denied (regardless of priority. Spec §9.3 "deny first").
/// - Next, if `RequireMfa` matches, MFA is required (MFA wins even if an allow policy matches at the same time).
/// - The rest are `Allow`. The match with the highest priority (smallest priority; ties stable by ascending `policy_code`) is recorded.
/// - If none match, `default_effect` applies (on default deny, `policy_code` is kept in the audit as the fixed value
///   `(default)`).
/// - **If the RP requested MFA via a reserved word, it is required regardless of policies** (ADR-0043).
///   If a method-specifying policy matches at the same time, "any second factor" is added to the method specification and **both**
///   must be satisfied.
pub fn evaluate_policies(
    policies: &[AuthenticationPolicy],
    ctx: &AuthenticationContext<'_>,
    default_effect: DefaultPolicyEffect,
) -> PolicyDecision {
    let mut matched: Vec<&AuthenticationPolicy> = policies
        .iter()
        .filter(|p| p.enabled && p.conditions.matches(ctx))
        .collect();
    // Ascending priority (ties deterministically by ascending policy_code).
    matched.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.policy_code.cmp(&b.policy_code))
    });

    if let Some(deny) = matched.iter().find(|p| p.effect == PolicyEffect::Deny) {
        return PolicyDecision::Deny {
            policy_code: deny.policy_code.clone(),
        };
    }
    // Method specifications are looked at before MFA requirements. `require_mfa` is "adding one second factor is enough", but
    // `require_specific_method` is "do not pass unless that method", the narrower requirement.
    // In reverse order, a user under a WebAuthn-required policy would pass with TOTP alone.
    let requirements: Vec<MethodRequirement> = matched
        .iter()
        .filter(|p| p.effect == PolicyEffect::RequireSpecificMethod)
        .map(|p| MethodRequirement {
            policy_code: p.policy_code.clone(),
            requirement: p.effect_params.clone().unwrap_or_default(),
        })
        .collect();
    if !requirements.is_empty() {
        let mut requirements = requirements;
        // Method specification and the reserved-word requirement are separate axes, so **both** must be satisfied. Returning the method specification
        // and stopping would make the RP's MFA requirement vanish whenever a single policy requires only `password`.
        if requests_mfa(ctx.requested_acr) {
            requirements.push(MethodRequirement {
                policy_code: BUILTIN_ACR_POLICY_CODE.to_string(),
                requirement: RequiredMethods {
                    methods: AuthenticationMethod::SECOND_FACTORS.to_vec(),
                    user_verification: false,
                },
            });
        }
        return PolicyDecision::RequireMethods { requirements };
    }
    if let Some(mfa) = matched
        .iter()
        .find(|p| p.effect == PolicyEffect::RequireMfa)
    {
        return PolicyDecision::RequireMfa {
            policy_code: mfa.policy_code.clone(),
        };
    }
    // When the RP requested MFA via a reserved word (ADR-0043 decision 1). Applied **regardless of policies**.
    // Without this, whether the request takes effect would depend on tenant settings, and "sending this value gives MFA"
    // could not be published (vocabulary that cannot be published cannot be communicated to RPs).
    if requests_mfa(ctx.requested_acr) {
        return PolicyDecision::RequireMfa {
            policy_code: BUILTIN_ACR_POLICY_CODE.to_string(),
        };
    }
    if let Some(allow) = matched.iter().find(|p| p.effect == PolicyEffect::Allow) {
        return PolicyDecision::Allow {
            matched_policy_code: Some(allow.policy_code.clone()),
        };
    }
    match default_effect {
        DefaultPolicyEffect::Allow => PolicyDecision::Allow {
            matched_policy_code: None,
        },
        DefaultPolicyEffect::Deny => PolicyDecision::Deny {
            policy_code: "(default)".to_string(),
        },
    }
}

#[cfg(test)]
mod ap3_tests {
    use super::*;
    use chrono::TimeZone;

    fn at(hour: u32, minute: u32) -> DateTime<Utc> {
        // 2026-08-05 is a Wednesday (weekday 3).
        Utc.with_ymd_and_hms(2026, 8, 5, hour, minute, 0).unwrap()
    }

    fn ctx_with(
        ip: Option<&'static str>,
        now: DateTime<Utc>,
        acr: &'static [String],
    ) -> AuthenticationContext<'static> {
        AuthenticationContext {
            application_id: None,
            user_id: Uuid::nil(),
            ip_address: ip,
            now,
            requested_acr: acr,
        }
    }

    #[test]
    fn ipv4_cidr_matches_only_inside_the_range() {
        let range = IpRange::parse("192.0.2.128/25").unwrap();
        assert!(range.contains("192.0.2.130".parse().unwrap()));
        assert!(range.contains("192.0.2.255".parse().unwrap()));
        assert!(!range.contains("192.0.2.127".parse().unwrap()));
        assert!(!range.contains("192.0.3.130".parse().unwrap()));
    }

    #[test]
    fn a_bare_address_is_a_single_host_range() {
        let range = IpRange::parse("203.0.113.7").unwrap();
        assert!(range.contains("203.0.113.7".parse().unwrap()));
        assert!(!range.contains("203.0.113.8".parse().unwrap()));
    }

    #[test]
    fn ipv6_cidr_matches_on_the_prefix() {
        let range = IpRange::parse("2001:db8:abcd::/48").unwrap();
        assert!(range.contains("2001:db8:abcd:1::1".parse().unwrap()));
        assert!(!range.contains("2001:db8:abce::1".parse().unwrap()));
    }

    /// v4 and v6 are not matched across. Equating them would create gaps like
    /// "coming via IPv6 escapes IPv4 deny ranges".
    #[test]
    fn address_families_do_not_cross_match() {
        let v4 = IpRange::parse("0.0.0.0/0").unwrap();
        assert!(!v4.contains("::1".parse().unwrap()));
    }

    #[test]
    fn malformed_cidrs_are_rejected_at_validation_time() {
        assert!(IpRange::parse("192.0.2.0/33").is_err());
        assert!(IpRange::parse("not-an-ip").is_err());
        assert!(IpRange::parse("192.0.2.0/abc").is_err());
    }

    /// For requests without evaluation inputs, policies with network conditions do not match.
    #[test]
    fn a_network_condition_does_not_match_without_a_client_ip() {
        let conditions = PolicyConditions {
            ip_cidrs: vec!["10.0.0.0/8".to_string()],
            ..Default::default()
        };
        assert!(!conditions.matches(&ctx_with(None, at(12, 0), &[])));
        assert!(conditions.matches(&ctx_with(Some("10.1.2.3"), at(12, 0), &[])));
        assert!(!conditions.matches(&ctx_with(Some("192.0.2.1"), at(12, 0), &[])));
    }

    #[test]
    fn a_time_window_matches_inside_the_range_only() {
        let window = TimeWindow {
            days: vec![],
            start_minute: 9 * 60,
            end_minute: 18 * 60,
            utc_offset_minutes: 0,
        };
        assert!(window.contains(at(9, 0)));
        assert!(window.contains(at(17, 59)));
        assert!(
            !window.contains(at(18, 0)),
            "the end time is exclusive (half-open interval)"
        );
        assert!(!window.contains(at(8, 59)));
    }

    /// A window crossing midnight (22:00-06:00) treats the next day's early morning as "the previous day's window" too. Getting this
    /// wrong combined with weekday specification would make a window starting Friday 22:00 end at Saturday 00:00.
    #[test]
    fn a_window_that_crosses_midnight_keeps_the_starting_day() {
        let window = TimeWindow {
            days: vec![3], // Wednesday
            start_minute: 22 * 60,
            end_minute: 6 * 60,
            utc_offset_minutes: 0,
        };
        assert!(
            window.contains(at(23, 0)),
            "Wednesday 23:00 is inside the window"
        );
        // Thursday 02:00 is the continuation of "the window starting Wednesday".
        let thursday_early = Utc.with_ymd_and_hms(2026, 8, 6, 2, 0, 0).unwrap();
        assert!(window.contains(thursday_early));
        // Thursday 23:00 belongs to the window starting Thursday, so it does not match a Wednesday specification.
        let thursday_night = Utc.with_ymd_and_hms(2026, 8, 6, 23, 0, 0).unwrap();
        assert!(!window.contains(thursday_night));
    }

    #[test]
    fn the_utc_offset_shifts_the_window() {
        // JST 09:00-18:00 = UTC 00:00-09:00.
        let window = TimeWindow {
            days: vec![],
            start_minute: 9 * 60,
            end_minute: 18 * 60,
            utc_offset_minutes: 540,
        };
        assert!(window.contains(at(1, 0)), "UTC 01:00 = JST 10:00");
        assert!(!window.contains(at(10, 0)), "UTC 10:00 = JST 19:00");
    }

    #[test]
    fn requested_acr_matches_any_of_the_requested_values() {
        let conditions = PolicyConditions {
            requested_acr: vec!["urn:mace:incommon:iap:silver".to_string()],
            ..Default::default()
        };
        let requested = vec!["urn:mace:incommon:iap:silver".to_string()];
        assert!(conditions.matches(&ctx_with(
            None,
            at(12, 0),
            Box::leak(requested.into_boxed_slice())
        )));
        assert!(!conditions.matches(&ctx_with(None, at(12, 0), &[])));
    }

    #[test]
    fn required_methods_are_satisfied_by_any_listed_method() {
        let requirement = RequiredMethods {
            methods: vec![AuthenticationMethod::WebAuthn, AuthenticationMethod::Totp],
            user_verification: false,
        };
        assert!(requirement.satisfied_by(&[AuthenticationMethod::Totp], false));
        assert!(requirement.satisfied_by(
            &[
                AuthenticationMethod::Password,
                AuthenticationMethod::WebAuthn
            ],
            false
        ));
        assert!(!requirement.satisfied_by(&[AuthenticationMethod::Password], false));
    }

    /// UV required means "even if the method matches, it does not pass without UV" (§12.2).
    #[test]
    fn user_verification_is_required_independently_of_the_method() {
        let requirement = RequiredMethods {
            methods: vec![AuthenticationMethod::WebAuthn],
            user_verification: true,
        };
        assert!(!requirement.satisfied_by(&[AuthenticationMethod::WebAuthn], false));
        assert!(requirement.satisfied_by(&[AuthenticationMethod::WebAuthn], true));
    }

    /// Method specification takes effect before MFA requirements. Otherwise a "WebAuthn required" user would pass with TOTP.
    #[test]
    fn a_specific_method_requirement_wins_over_require_mfa() {
        let mut specific = policy_for_test("specific", 10, PolicyEffect::RequireSpecificMethod);
        specific.effect_params = Some(RequiredMethods {
            methods: vec![AuthenticationMethod::WebAuthn],
            user_verification: false,
        });
        let mfa = policy_for_test("mfa", 1, PolicyEffect::RequireMfa);
        let decision = evaluate_policies(
            &[mfa, specific],
            &ctx_with(None, at(12, 0), &[]),
            DefaultPolicyEffect::Allow,
        );
        let PolicyDecision::RequireMethods { requirements } = &decision else {
            panic!("expected RequireMethods, got {decision:?}");
        };
        assert_eq!(requirements.len(), 1);
        assert_eq!(requirements[0].policy_code, "specific");
        assert!(decision
            .unmet_method_requirement(&[AuthenticationMethod::Totp], false)
            .is_some());
        assert!(decision
            .unmet_method_requirement(&[AuthenticationMethod::WebAuthn], true)
            .is_none());
    }

    /// **All** matching method specifications are held and all must be satisfied. Taking only the first would
    /// break the convention "AND is expressed by splitting into 2 policies", letting one pass by satisfying just the higher-priority
    /// one and ignoring the other.
    #[test]
    fn every_matching_method_requirement_must_be_satisfied() {
        let mut webauthn = policy_for_test("webauthn", 1, PolicyEffect::RequireSpecificMethod);
        webauthn.effect_params = Some(RequiredMethods {
            methods: vec![AuthenticationMethod::WebAuthn],
            user_verification: false,
        });
        let mut totp = policy_for_test("totp", 2, PolicyEffect::RequireSpecificMethod);
        totp.effect_params = Some(RequiredMethods {
            methods: vec![AuthenticationMethod::Totp],
            user_verification: false,
        });
        let decision = evaluate_policies(
            &[webauthn, totp],
            &ctx_with(None, at(12, 0), &[]),
            DefaultPolicyEffect::Allow,
        );
        let PolicyDecision::RequireMethods { requirements } = &decision else {
            panic!("expected RequireMethods, got {decision:?}");
        };
        assert_eq!(
            requirements.len(),
            2,
            "holds all matching method specifications"
        );

        // Satisfying only the higher-priority WebAuthn still leaves the TOTP requirement.
        let unmet = decision
            .unmet_method_requirement(&[AuthenticationMethod::WebAuthn], true)
            .expect("totp requirement is still unmet");
        assert_eq!(unmet.policy_code, "totp");
        // Satisfying both passes.
        assert!(decision
            .unmet_method_requirement(
                &[AuthenticationMethod::WebAuthn, AuthenticationMethod::Totp],
                true
            )
            .is_none());
    }

    /// Deny takes precedence even over method specifications (spec §9.3).
    #[test]
    fn deny_still_wins_over_a_specific_method_requirement() {
        let mut specific = policy_for_test("specific", 1, PolicyEffect::RequireSpecificMethod);
        specific.effect_params = Some(RequiredMethods {
            methods: vec![AuthenticationMethod::WebAuthn],
            user_verification: false,
        });
        let deny = policy_for_test("deny", 99, PolicyEffect::Deny);
        assert!(matches!(
            evaluate_policies(
                &[specific, deny],
                &ctx_with(None, at(12, 0), &[]),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Deny { .. }
        ));
    }

    /// ADR-0043 decision 1. Even with no policies and a default of allow, the reserved-word request alone makes it MFA.
    /// Without this, "sending this value gives MFA" could not be published.
    #[test]
    fn the_reserved_word_requires_mfa_without_any_policy() {
        let requested = [ACR_MULTI_FACTOR.to_string()];
        assert!(matches!(
            evaluate_policies(
                &[],
                &AuthenticationContext {
                    application_id: None,
                    user_id: Uuid::nil(),
                    ip_address: None,
                    now: at(12, 0),
                    requested_acr: &requested,
                },
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::RequireMfa { ref policy_code } if policy_code == BUILTIN_ACR_POLICY_CODE
        ));
    }

    /// Unknown strings remain merely "inputs to policy conditions" as before, so as not to break tenants writing
    /// their own values in conditions.
    #[test]
    fn an_unknown_acr_value_requires_nothing_by_itself() {
        let requested = ["urn:example:loa2".to_string()];
        assert!(matches!(
            evaluate_policies(
                &[],
                &AuthenticationContext {
                    application_id: None,
                    user_id: Uuid::nil(),
                    ip_address: None,
                    now: at(12, 0),
                    requested_acr: &requested,
                },
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Allow { .. }
        ));
    }

    /// The RP's request does not vanish even with a method-specifying policy. Returning the method specification and stopping would
    /// let the MFA requirement slip through whenever a single policy requires only `password`.
    #[test]
    fn the_reserved_word_survives_a_specific_method_policy() {
        let mut specific = policy_for_test("pwd-only", 10, PolicyEffect::RequireSpecificMethod);
        specific.effect_params = Some(RequiredMethods {
            methods: vec![AuthenticationMethod::Password],
            user_verification: false,
        });
        let requested = [ACR_MULTI_FACTOR.to_string()];
        let decision = evaluate_policies(
            &[specific],
            &AuthenticationContext {
                application_id: None,
                user_id: Uuid::nil(),
                ip_address: None,
                now: at(12, 0),
                requested_acr: &requested,
            },
            DefaultPolicyEffect::Allow,
        );
        // Password alone does not satisfy it (the second-factor requirement remains).
        assert!(decision
            .unmet_method_requirement(&[AuthenticationMethod::Password], false)
            .is_some());
        // Password + TOTP satisfies both.
        assert!(decision
            .unmet_method_requirement(
                &[AuthenticationMethod::Password, AuthenticationMethod::Totp],
                false
            )
            .is_none());
    }

    /// Deny takes precedence over reserved words (spec §9.3). It does not pass just because it was requested.
    #[test]
    fn deny_still_wins_over_the_reserved_word() {
        let deny = policy_for_test("deny-all", 1, PolicyEffect::Deny);
        let requested = [ACR_MULTI_FACTOR.to_string()];
        assert!(matches!(
            evaluate_policies(
                &[deny],
                &AuthenticationContext {
                    application_id: None,
                    user_id: Uuid::nil(),
                    ip_address: None,
                    now: at(12, 0),
                    requested_acr: &requested,
                },
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Deny { .. }
        ));
    }

    fn policy_for_test(code: &str, priority: i32, effect: PolicyEffect) -> AuthenticationPolicy {
        AuthenticationPolicy {
            id: Uuid::nil(),
            tenant_id: TenantId::from(Uuid::nil()),
            policy_code: code.to_string(),
            policy_name: code.to_string(),
            priority,
            enabled: true,
            effect,
            effect_params: None,
            conditions: PolicyConditions::default(),
            created_at: at(0, 0),
            updated_at: at(0, 0),
        }
    }

    /// `require_specific_method` is meaningless without a requirement (it would line up looking like `allow`).
    #[test]
    fn effect_params_must_match_the_effect() {
        assert!(AuthenticationPolicy::validate_effect_params(
            PolicyEffect::RequireSpecificMethod,
            None
        )
        .is_err());
        assert!(AuthenticationPolicy::validate_effect_params(
            PolicyEffect::RequireSpecificMethod,
            Some(&RequiredMethods::default())
        )
        .is_err());
        assert!(AuthenticationPolicy::validate_effect_params(
            PolicyEffect::Allow,
            Some(&RequiredMethods {
                methods: vec![AuthenticationMethod::Totp],
                user_verification: false,
            })
        )
        .is_err());
        assert!(AuthenticationPolicy::validate_effect_params(PolicyEffect::Deny, None).is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap()
    }

    fn tenant() -> TenantId {
        TenantId::from(Uuid::from_u128(0x0197_0000_0000_7000_8000_0000_0000_0001))
    }

    fn policy(
        code: &str,
        priority: i32,
        effect: PolicyEffect,
        conditions: PolicyConditions,
    ) -> AuthenticationPolicy {
        AuthenticationPolicy {
            id: Uuid::new_v4(),
            effect_params: None,
            tenant_id: tenant(),
            policy_code: code.to_string(),
            policy_name: code.to_string(),
            priority,
            enabled: true,
            effect,
            conditions,
            created_at: fixed_now(),
            updated_at: fixed_now(),
        }
    }

    /// The app used in conditions (fixed value for tests).
    fn an_application() -> Uuid {
        Uuid::from_u128(0x0199_0000_0000_7000_8000_0000_0000_0001)
    }

    /// An app different from the one above.
    fn another_application() -> Uuid {
        Uuid::from_u128(0x0199_0000_0000_7000_8000_0000_0000_0002)
    }

    fn ctx(user_id: Uuid, application_id: Option<Uuid>) -> AuthenticationContext<'static> {
        AuthenticationContext {
            application_id,
            user_id,
            ip_address: None,
            now: fixed_now(),
            requested_acr: &[],
        }
    }

    #[test]
    fn no_policies_falls_back_to_default_effect() {
        let user = Uuid::new_v4();
        assert_eq!(
            evaluate_policies(&[], &ctx(user, None), DefaultPolicyEffect::Allow),
            PolicyDecision::Allow {
                matched_policy_code: None
            }
        );
        assert_eq!(
            evaluate_policies(&[], &ctx(user, None), DefaultPolicyEffect::Deny),
            PolicyDecision::Deny {
                policy_code: "(default)".to_string()
            }
        );
    }

    #[test]
    fn empty_conditions_match_everything() {
        let user = Uuid::new_v4();
        let p = policy(
            "all",
            100,
            PolicyEffect::RequireMfa,
            PolicyConditions::default(),
        );
        assert_eq!(
            evaluate_policies(
                &[p],
                &ctx(user, Some(an_application())),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::RequireMfa {
                policy_code: "all".to_string()
            }
        );
    }

    /// Spec §9.3: deny always takes precedence over allow and MFA (regardless of priority values).
    #[test]
    fn deny_wins_over_allow_and_mfa_regardless_of_priority() {
        let user = Uuid::new_v4();
        let policies = vec![
            policy(
                "allow-any",
                1,
                PolicyEffect::Allow,
                PolicyConditions::default(),
            ),
            policy(
                "mfa-any",
                2,
                PolicyEffect::RequireMfa,
                PolicyConditions::default(),
            ),
            policy(
                "deny-any",
                999,
                PolicyEffect::Deny,
                PolicyConditions::default(),
            ),
        ];
        assert_eq!(
            evaluate_policies(&policies, &ctx(user, None), DefaultPolicyEffect::Allow),
            PolicyDecision::Deny {
                policy_code: "deny-any".to_string()
            }
        );
    }

    /// Spec §9.3: additional authentication (MFA) policies take precedence over plain allow.
    #[test]
    fn require_mfa_wins_over_allow() {
        let user = Uuid::new_v4();
        let policies = vec![
            policy(
                "allow-any",
                1,
                PolicyEffect::Allow,
                PolicyConditions::default(),
            ),
            policy(
                "mfa-any",
                100,
                PolicyEffect::RequireMfa,
                PolicyConditions::default(),
            ),
        ];
        assert_eq!(
            evaluate_policies(&policies, &ctx(user, None), DefaultPolicyEffect::Allow),
            PolicyDecision::RequireMfa {
                policy_code: "mfa-any".to_string()
            }
        );
    }

    #[test]
    fn disabled_policies_are_ignored() {
        let user = Uuid::new_v4();
        let mut p = policy(
            "deny-any",
            1,
            PolicyEffect::Deny,
            PolicyConditions::default(),
        );
        p.enabled = false;
        assert_eq!(
            evaluate_policies(&[p], &ctx(user, None), DefaultPolicyEffect::Allow),
            PolicyDecision::Allow {
                matched_policy_code: None
            }
        );
    }

    #[test]
    fn an_application_condition_limits_scope() {
        let user = Uuid::new_v4();
        let p = policy(
            "deny-legacy",
            1,
            PolicyEffect::Deny,
            PolicyConditions {
                application_ids: vec![an_application()],
                user_ids: vec![],
                ..Default::default()
            },
        );
        // Deny only the target app.
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(user, Some(an_application())),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Deny { .. }
        ));
        // Other clients and no client (portal) do not match.
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(user, Some(another_application())),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Allow { .. }
        ));
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(user, None),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Allow { .. }
        ));
    }

    #[test]
    fn user_condition_limits_scope_and_conditions_are_anded() {
        let target = Uuid::new_v4();
        let other = Uuid::new_v4();
        let p = policy(
            "mfa-target-on-app",
            1,
            PolicyEffect::RequireMfa,
            PolicyConditions {
                application_ids: vec![an_application()],
                user_ids: vec![target],
                ..Default::default()
            },
        );
        // Holds when both conditions match (AND).
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(target, Some(an_application())),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::RequireMfa { .. }
        ));
        // Only one does not hold.
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(other, Some(an_application())),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Allow { .. }
        ));
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(target, Some(another_application())),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Allow { .. }
        ));
    }

    /// When several policies with the same effect match, the first by ascending priority is recorded (for tracing in the audit).
    #[test]
    fn lowest_priority_value_wins_within_same_effect() {
        let user = Uuid::new_v4();
        let policies = vec![
            policy(
                "mfa-low",
                100,
                PolicyEffect::RequireMfa,
                PolicyConditions::default(),
            ),
            policy(
                "mfa-high",
                10,
                PolicyEffect::RequireMfa,
                PolicyConditions::default(),
            ),
        ];
        assert_eq!(
            evaluate_policies(&policies, &ctx(user, None), DefaultPolicyEffect::Allow),
            PolicyDecision::RequireMfa {
                policy_code: "mfa-high".to_string()
            }
        );
    }

    #[test]
    fn effect_round_trips_through_str() {
        for effect in [
            PolicyEffect::Allow,
            PolicyEffect::Deny,
            PolicyEffect::RequireMfa,
        ] {
            assert_eq!(PolicyEffect::parse(effect.as_str()).unwrap(), effect);
        }
        assert!(PolicyEffect::parse("unknown").is_err());
    }

    #[test]
    fn policy_code_validation_rejects_unsafe_values() {
        assert!(AuthenticationPolicy::validate_code("deny-high_risk.v2").is_ok());
        assert!(AuthenticationPolicy::validate_code("").is_err());
        assert!(AuthenticationPolicy::validate_code(&"a".repeat(101)).is_err());
        assert!(AuthenticationPolicy::validate_code("スペース入り code").is_err());
        assert!(AuthenticationPolicy::validate_code("slash/code").is_err());
    }

    #[test]
    fn lockout_policy_locks_only_at_threshold() {
        let policy = LockoutPolicy {
            max_failed_attempts: 5,
            lock_duration_secs: 900,
            max_lock_duration_secs: 900,
        };
        let now = fixed_now();
        assert_eq!(policy.locked_until_after_failure(4, now), None);
        assert_eq!(
            policy.locked_until_after_failure(5, now),
            Some(now + chrono::Duration::seconds(900))
        );
        assert!(policy.locked_until_after_failure(6, now).is_some());
    }

    /// AP6: the lock duration doubles each time failures pile up, capped at the upper bound.
    #[test]
    fn lock_duration_doubles_until_it_reaches_the_cap() {
        let policy = LockoutPolicy {
            max_failed_attempts: 5,
            lock_duration_secs: 900,
            max_lock_duration_secs: 7_200,
        };
        // Exactly at the threshold is the first duration. Then doubled with each further failure.
        assert_eq!(policy.lock_duration_secs_for(5), 900);
        assert_eq!(policy.lock_duration_secs_for(6), 1_800);
        assert_eq!(policy.lock_duration_secs_for(7), 3_600);
        assert_eq!(policy.lock_duration_secs_for(8), 7_200);
        // Once the upper bound is reached it grows no further.
        assert_eq!(policy.lock_duration_secs_for(9), 7_200);
        assert_eq!(policy.lock_duration_secs_for(i32::MAX), 7_200);
    }

    /// Even if the upper bound is set shorter than the first, the first lock duration always applies (so a misconfiguration
    /// does not effectively disable locking).
    #[test]
    fn a_cap_below_the_base_duration_does_not_shorten_the_first_lock() {
        let policy = LockoutPolicy {
            max_failed_attempts: 3,
            lock_duration_secs: 900,
            max_lock_duration_secs: 60,
        };
        assert_eq!(policy.lock_duration_secs_for(3), 900);
        assert_eq!(policy.lock_duration_secs_for(30), 900);
    }

    /// The list of stages is ordered "largest excess first". SQL `CASE` takes the first matching WHEN, so
    /// in reverse order the first duration would always be chosen and progression would not work.
    #[test]
    fn the_escalation_ladder_is_ordered_from_the_longest_lock_down() {
        let policy = LockoutPolicy {
            max_failed_attempts: 5,
            lock_duration_secs: 900,
            max_lock_duration_secs: 3_600,
        };
        let ladder = policy.escalation_ladder();
        assert_eq!(ladder, vec![(7, 3_600), (6, 1_800), (5, 900)]);
        // Each stage matches the domain formula (the SQL side only chooses from this list).
        for (threshold, duration) in &ladder {
            assert_eq!(policy.lock_duration_secs_for(*threshold), *duration);
        }
    }

    /// A non-progressive setting (upper bound = first) has only one stage.
    #[test]
    fn a_fixed_duration_policy_yields_a_single_step() {
        let policy = LockoutPolicy {
            max_failed_attempts: 10,
            lock_duration_secs: 900,
            max_lock_duration_secs: 900,
        };
        assert_eq!(policy.escalation_ladder(), vec![(10, 900)]);
    }

    #[test]
    fn conditions_serde_round_trip() {
        let user = Uuid::new_v4();
        let conditions = PolicyConditions {
            application_ids: vec![an_application()],
            user_ids: vec![user],
            ..Default::default()
        };
        let json = serde_json::to_string(&conditions).unwrap();
        assert_eq!(
            serde_json::from_str::<PolicyConditions>(&json).unwrap(),
            conditions
        );
        // Empty conditions become `{}` (keeps the DB JSON column concise).
        assert_eq!(
            serde_json::to_string(&PolicyConditions::default()).unwrap(),
            "{}"
        );
        // Unknown keys are rejected (prevents accidents where a typo makes a condition ignored and everything allowed).
        assert!(serde_json::from_str::<PolicyConditions>(r#"{"clientIds": []}"#).is_err());
    }
}
