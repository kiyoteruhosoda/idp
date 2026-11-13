//! View models web receives from the api's JSON admin API (`/admin/*`) (ADR-0007 §4).
//!
//! These are read-only structs for receiving, on the web side, the same JSON shapes as the api's OpenAPI DTOs (`ClientResponse` etc.).
//! The api's admin API is a contract published via OpenAPI, and web, as one of its consumers,
//! receives it with its own view models (the true contract for internal authentication lives in `assay-contracts`). Consistency is verified by E2E.

use serde::Deserialize;

/// Public representation of a client (RP) (response element of `GET /admin/clients` and `/admin/clients/{id}`).
#[derive(Debug, Clone, Deserialize)]
pub struct ClientView {
    pub id: String,
    pub client_id: String,
    pub client_type: String,
    pub client_status: String,
    pub app_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    #[allow(dead_code)]
    pub response_types: Vec<String>,
    pub scopes: Vec<String>,
    pub token_endpoint_auth_method: String,
    /// Verification keys for `private_key_jwt` (JWK Set JSON; ADR-0030). Public keys only.
    #[serde(default)]
    pub jwks: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// One page of the client list (`GET /admin/clients`; G7).
#[derive(Debug, Clone, Deserialize)]
pub struct ClientListView {
    pub clients: Vec<ClientView>,
    /// Total count before paging. Used for the "N in total" display and whether there is a next page.
    pub total: i64,
    /// Page size the api actually applied (after clamping). Used as the paging step.
    pub limit: i64,
    #[allow(dead_code)]
    pub offset: i64,
}

/// Creation response (`POST /admin/clients`). `client_secret` is included only for confidential clients.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientCreatedView {
    #[serde(flatten)]
    pub client: ClientView,
    #[serde(default)]
    pub client_secret: Option<String>,
}

/// Secret reissue response (`POST /admin/clients/{id}/secret`).
#[derive(Debug, Clone, Deserialize)]
pub struct ClientSecretView {
    #[allow(dead_code)]
    pub client_id: String,
    pub client_secret: String,
}

/// One audit log row (response element of `GET /admin/audit-logs`; design spec §7).
#[derive(Debug, Clone, Deserialize)]
pub struct AuditLogView {
    #[allow(dead_code)]
    pub id: i64,
    pub event_type: String,
    pub occurred_at: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub user_agent: Option<String>,
    pub result: String,
    #[serde(default)]
    pub reason: Option<String>,
    pub correlation_id: String,
}

/// The api's error response body (`{ "error": code, "message": msg }`).
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorBody {
    #[allow(dead_code)]
    pub error: String,
    pub message: String,
}

/// Public representation of a signing key (response element of `GET /admin/signing-keys`).
#[derive(Debug, Clone, Deserialize)]
pub struct SigningKeyView {
    pub kid: String,
    pub algorithm: String,
    pub status: String,
    pub not_before: String,
    pub not_after: String,
    pub created_at: String,
    /// Whether this key is currently used for signing. **It can't be read from `status`** -- there can be several ACTIVE keys, and only
    /// one signs. The rule deciding which lives in core and is not available to web, so the api decides and returns it.
    /// Defaults to `false` so screens don't break with an old api (that doesn't return this field).
    #[serde(default)]
    pub is_current_signer: bool,
    /// Whether the key is published but not yet used for signing (`not_before` is in the future).
    #[serde(default)]
    pub is_pending: bool,
}

/// Public representation of an app (response element of `GET /admin/applications`; ADR-0054).
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationView {
    pub id: String,
    pub display_name: String,
    /// `ACTIVE` / `DISABLED`.
    pub status: String,
    /// `EVERYONE` / `INDIVIDUAL`.
    pub assignment_mode: String,
    #[serde(default)]
    pub bindings: Vec<ApplicationBindingView>,
    #[serde(default)]
    pub assigned_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl ApplicationView {
    /// Whether it is usable (a predicate so templates don't compare status strings).
    pub fn is_active(&self) -> bool {
        self.status == "ACTIVE"
    }

    /// Whether only assigned users can use it.
    pub fn is_individual(&self) -> bool {
        self.assignment_mode == "INDIVIDUAL"
    }

    /// Whether it has login bindings (OIDC, SAML). ⚠ Removing them takes that integration outside the decision (anyone can get in)
    /// (a consequence of ADR-0054), so warn before removing.
    pub fn has_login_binding(&self) -> bool {
        self.bindings
            .iter()
            .any(|b| b.kind == "oidc" || b.kind == "saml")
    }

    /// ⚠ **The state where nobody can get in** ("individual" with an empty roster).
    /// Mixing it up with "everyone" cuts everyone off, so it is highlighted in the list.
    pub fn admits_nobody(&self) -> bool {
        self.is_active() && self.is_individual() && self.assigned_count == 0
    }
}

/// Translation key for the binding kind's display name (so templates don't compare kind strings).
/// Unknown kinds are shown as spelled (screens don't break even with a new api and an old web).
pub fn binding_kind_label_key(kind: &str) -> &str {
    match kind {
        "oidc" => "admin-applications-kind-oidc",
        "saml" => "admin-applications-kind-saml",
        "service_account" => "admin-applications-kind-service-account",
        "resource" => "admin-applications-kind-resource",
        other => other,
    }
}

/// Public representation of one binding (ADR-0059).
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationBindingView {
    pub id: String,
    /// `oidc` / `saml` / `service_account` / `resource`.
    pub kind: String,
    /// `client_id` for login and service accounts, `entity_id` for SAML, and
    /// `resource_uri` for audiences. `None` if the counterpart is gone.
    #[serde(default)]
    pub identifier: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

impl ApplicationBindingView {
    /// Translation key for the kind's display name (so templates don't compare kind strings).
    /// Unknown kinds are shown as spelled (screens don't break even with a new api and an old web).
    pub fn kind_label_key(&self) -> &str {
        binding_kind_label_key(&self.kind)
    }

    /// Whether it is a service account binding (shows the server icon).
    pub fn is_service_account(&self) -> bool {
        self.kind == "service_account"
    }
}

/// Response with binding candidates (`GET /admin/applications/{id}/binding-candidates`; ADR-0067).
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationBindingCandidateListView {
    #[serde(default)]
    pub candidates: Vec<ApplicationBindingCandidateView>,
}

/// One binding candidate.
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationBindingCandidateView {
    /// `oidc` / `saml` / `service_account` / `resource`.
    pub kind: String,
    /// Value sent when binding (`client_id`, the SP's internal ID, the audience URI).
    pub reference: String,
    /// Value humans tell apart (`client_id`, `entity_id`, the audience URI).
    pub identifier: String,
    pub display_name: String,
    /// The app that currently has this counterpart as a binding.
    #[serde(default)]
    pub application_id: Option<String>,
    #[serde(default)]
    pub application_name: Option<String>,
}

impl ApplicationBindingCandidateView {
    /// The choice value (`<kind>:<counterpart>`). Kinds contain no `:`, so splitting at the first `:` restores it
    /// (audience URIs and SAML entityIDs contain `:`, but only on the counterpart side).
    pub fn choice_value(&self) -> String {
        format!("{}:{}", self.kind, self.reference)
    }

    /// Translation key for the kind's display name.
    pub fn kind_label_key(&self) -> &str {
        binding_kind_label_key(&self.kind)
    }
}

/// Turns a choice value ([`ApplicationBindingCandidateView::choice_value`]) back into kind and counterpart.
/// `None` if the shape doesn't match.
pub fn parse_binding_choice(value: &str) -> Option<(&str, &str)> {
    let (kind, reference) = value.trim().split_once(':')?;
    let reference = reference.trim();
    if kind.is_empty() || reference.is_empty() {
        return None;
    }
    Some((kind, reference))
}

/// Candidates grouped by kind (one `<optgroup>` on screen).
#[derive(Debug, Clone)]
pub struct BindingCandidateGroup {
    /// Translation key for the kind's display name.
    pub label_key: &'static str,
    pub candidates: Vec<ApplicationBindingCandidateView>,
}

/// Groups candidates in kind order (login OIDC, SAML, service account, audience). Empty kinds are omitted.
/// Unknown kinds (new api, old web) are discarded -- even if chosen, this web wouldn't know how to send them.
pub fn group_binding_candidates(
    candidates: Vec<ApplicationBindingCandidateView>,
) -> Vec<BindingCandidateGroup> {
    const KINDS: [(&str, &str); 4] = [
        ("oidc", "admin-applications-kind-oidc"),
        ("saml", "admin-applications-kind-saml"),
        ("service_account", "admin-applications-kind-service-account"),
        ("resource", "admin-applications-kind-resource"),
    ];
    KINDS
        .into_iter()
        .filter_map(|(kind, label_key)| {
            let members: Vec<_> = candidates
                .iter()
                .filter(|c| c.kind == kind)
                .cloned()
                .collect();
            (!members.is_empty()).then_some(BindingCandidateGroup {
                label_key,
                candidates: members,
            })
        })
        .collect()
}

/// App list response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationListView {
    pub applications: Vec<ApplicationView>,
    /// `record_only` / `enforce`.
    #[serde(default)]
    pub enforcement: String,
}

impl ApplicationListView {
    /// Whether the decision has not yet reached the point of refusing (= assignments not in effect).
    pub fn is_record_only(&self) -> bool {
        self.enforcement != "enforce"
    }
}

/// App detail response (one list item + roster).
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationDetailView {
    #[serde(flatten)]
    pub application: ApplicationView,
    #[serde(default)]
    pub assigned: Vec<ApplicationAssignmentView>,
    /// Assigned service accounts (ADR-0059). Old apis don't return it, so it defaults to empty.
    #[serde(default)]
    pub assigned_service_accounts: Vec<ApplicationServiceAccountAssignmentView>,
    /// `record_only` / `enforce`.
    #[serde(default)]
    pub enforcement: String,
}

impl ApplicationDetailView {
    /// Whether the decision has not yet reached the point of refusing (= assignments not in effect).
    pub fn is_record_only(&self) -> bool {
        self.enforcement != "enforce"
    }
}

/// One assigned user row.
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationAssignmentView {
    pub user_id: String,
    pub sub: String,
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    /// Status of the user account itself (`ACTIVE` / `DISABLED` / `LOCKED`).
    pub status: String,
    pub assigned_at: String,
}

impl ApplicationAssignmentView {
    /// Whether the user account itself is stopped. ⚠ The assignment remains, so the roster shows it separately.
    pub fn is_user_active(&self) -> bool {
        self.status == "ACTIVE"
    }
}

/// One assigned service account row.
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationServiceAccountAssignmentView {
    pub client_id: String,
    pub app_name: String,
    /// Client status (`ACTIVE` / `DISABLED` / `DELETED`).
    pub status: String,
    pub assigned_at: String,
}

impl ApplicationServiceAccountAssignmentView {
    /// Whether the client is running. ⚠ The assignment remains, so the list shows it separately.
    pub fn is_client_active(&self) -> bool {
        self.status == "ACTIVE"
    }
}

/// Response with "people who can get in now" (the copy source before switching from "everyone" to "individual").
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationCurrentUsersView {
    #[serde(default)]
    pub users: Vec<ApplicationCurrentUserView>,
    #[serde(default)]
    pub total: i64,
    /// ⚠ If true, "not everyone could be listed". The screen says exactly that.
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationCurrentUserView {
    pub user_id: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// Public representation of a protected resource (the audience in `aud`) (response element of `GET /admin/resources`; ADR-0042).
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceView {
    pub id: String,
    /// The exact value put in a token's `aud`.
    pub resource_uri: String,
    pub display_name: String,
    /// `ACTIVE` / `DISABLED`.
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

impl ResourceView {
    /// Whether it can be used as the audience of new tokens (a predicate so templates don't compare status strings).
    pub fn is_active(&self) -> bool {
        self.status == "ACTIVE"
    }
}

/// Protected resource list response.
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceListView {
    pub resources: Vec<ResourceView>,
}

/// Public representation of a SAML SP (client) (response element of `GET /admin/saml-service-providers`).
#[derive(Debug, Clone, Deserialize)]
pub struct SamlServiceProviderView {
    pub id: String,
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    /// Signing/encryption certificate (optional). Used as the edit form's initial value.
    #[serde(default)]
    pub x509_certificate: Option<String>,
    pub enabled: bool,
}

/// User creation response (`POST /admin/users`). A one-time link to hand to the user is returned only once (ADR-0062).
#[derive(Debug, Clone, Deserialize)]
pub struct UserCreatedView {
    #[allow(dead_code)]
    pub user_id: String,
    #[allow(dead_code)]
    pub sub: String,
    pub setup_url: String,
    pub setup_expires_at: String,
}

/// One member list item (`GET /admin/members`; HOME or GUEST; ADR-0009 §3).
#[derive(Debug, Clone, Deserialize)]
pub struct MemberView {
    pub user_id: String,
    #[serde(default)]
    pub email: Option<String>,
    /// Primary login identifier (username). `None` when the api omits it.
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    /// `HOME` or `GUEST`.
    pub membership_type: String,
    /// `INVITED` or `ACTIVE`.
    pub status: String,
    /// Status of the user account itself (`ACTIVE` / `DISABLED` / `LOCKED`). `None` for nonexistent users.
    #[serde(default)]
    pub user_status: Option<String>,
    /// Whether a lock due to login failures is currently in place (AP6). The api returns a boolean with expiry already judged
    /// (web has no clock, so the expiry comparison is not redone on the web side).
    #[serde(default)]
    pub locked: bool,
    /// Provisional registration (ADR-0064). The user has not yet set credentials via the setup link.
    #[serde(default)]
    pub pending_setup: bool,
    /// Expiry of the provisional user's current setup link (RFC 3339, UTC).
    #[serde(default)]
    pub setup_link_expires_at: Option<String>,
    /// Provisional with no usable setup link (expired). A value judged at the time the api read it
    /// (web has no clock, so the expiry comparison is not redone; same as `locked`).
    #[serde(default)]
    pub setup_link_expired: bool,
    /// Admin note (ADR-0063). `None` if none is written.
    #[serde(default)]
    pub note: Option<AccountNoteView>,
}

impl MemberView {
    /// Name shown as the list heading (taken in the order email -> username).
    pub fn headline(&self) -> &str {
        self.email
            .as_deref()
            .or(self.preferred_username.as_deref())
            .unwrap_or("-")
    }

    /// Name added below the heading. Not repeated if equal to the heading (the same string twice is hard to read).
    pub fn secondary_names(&self) -> Vec<&str> {
        let headline = self.headline();
        let mut out: Vec<&str> = Vec::new();
        for value in [self.preferred_username.as_deref(), self.name.as_deref()]
            .into_iter()
            .flatten()
        {
            if value != headline && !out.contains(&value) {
                out.push(value);
            }
        }
        out
    }
}

/// Admin note on an account (person or service account) (ADR-0063 / ADR-0065).
#[derive(Debug, Clone, Deserialize)]
pub struct AccountNoteView {
    pub text: String,
    /// RFC 3339 (UTC). On screen, `local-time.js` converts it to the viewer's time.
    pub updated_at: String,
}

impl AccountNoteView {
    /// First line shown in the list (truncated if long). The list is for finding things; the full text is read on the item's screen.
    pub fn excerpt(&self) -> Option<String> {
        const MAX_CHARS: usize = 60;
        let first = self.text.lines().next()?.trim();
        if first.is_empty() {
            return None;
        }
        let mut excerpt: String = first.chars().take(MAX_CHARS).collect();
        if first.chars().count() > MAX_CHARS || self.text.contains('\n') {
            excerpt.push('…');
        }
        Some(excerpt)
    }
}

/// One service account (`GET /admin/service-accounts/{client_id}`, one list row; ADR-0065).
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceAccountView {
    pub client_id: String,
    pub app_name: String,
    /// `ACTIVE` / `DISABLED`.
    pub status: String,
    /// RFC 3339 (UTC).
    pub created_at: String,
    /// Apps that have this service account as a binding.
    #[serde(default)]
    pub identity_of: Option<IdentityApplicationView>,
    #[serde(default)]
    pub note: Option<AccountNoteView>,
}

/// An app that has the service account as a binding.
#[derive(Debug, Clone, Deserialize)]
pub struct IdentityApplicationView {
    pub application_id: String,
    pub display_name: String,
}

/// One account list row (either `user` or `service_account` is present depending on `kind`; ADR-0065).
#[derive(Debug, Clone, Deserialize)]
pub struct AccountView {
    /// `user` / `service_account`.
    pub kind: String,
    #[serde(default)]
    pub user: Option<MemberView>,
    #[serde(default)]
    pub service_account: Option<ServiceAccountView>,
}

impl AccountView {
    /// Path to the item's screen (without the tenant prefix). The route differs per kind.
    pub fn path(&self) -> String {
        match (&self.user, &self.service_account) {
            (Some(m), _) => format!("/admin/members/{}", m.user_id),
            (None, Some(sa)) => format!("/admin/service-accounts/{}", sa.client_id),
            (None, None) => "/admin/accounts".to_string(),
        }
    }

    /// Heading (people: email -> username; service accounts: registered name).
    pub fn headline(&self) -> &str {
        match (&self.user, &self.service_account) {
            (Some(m), _) => m.headline(),
            (None, Some(sa)) => &sa.app_name,
            (None, None) => "-",
        }
    }

    /// Name added below the heading (people: username or full name; service accounts: `client_id`).
    pub fn secondary_names(&self) -> Vec<&str> {
        match (&self.user, &self.service_account) {
            (Some(m), _) => m.secondary_names(),
            (None, Some(sa)) => vec![sa.client_id.as_str()],
            (None, None) => Vec::new(),
        }
    }

    /// First line of the note shown in the list.
    pub fn note_excerpt(&self) -> Option<String> {
        match (&self.user, &self.service_account) {
            (Some(m), _) => m.note.as_ref()?.excerpt(),
            (None, Some(sa)) => sa.note.as_ref()?.excerpt(),
            (None, None) => None,
        }
    }
}

/// One page of the account list (`GET /admin/accounts`; ADR-0065).
#[derive(Debug, Clone, Deserialize)]
pub struct AccountListView {
    pub accounts: Vec<AccountView>,
    /// Kinds actually listed.
    #[allow(dead_code)]
    pub kinds: Vec<String>,
    /// Readable kinds (filter choices).
    pub readable_kinds: Vec<String>,
    /// Total count after filtering (before paging).
    pub total: i64,
    /// Page size the api actually applied (after clamping).
    pub limit: i64,
    #[allow(dead_code)]
    pub offset: i64,
}

/// Apps an account can use (`GET /admin/members/{user_id}/applications`,
/// `GET /admin/service-accounts/{client_id}/applications`; ADR-0063 / ADR-0065).
#[derive(Debug, Clone, Deserialize)]
pub struct AccountApplicationListView {
    pub applications: Vec<AccountApplicationView>,
    /// `record_only` / `enforce`.
    pub enforcement: String,
}

impl AccountApplicationListView {
    /// Count per availability (shown on the filter tags).
    pub fn count(&self, access: &str) -> usize {
        self.applications
            .iter()
            .filter(|a| a.access == access)
            .count()
    }
}

/// One app as seen from an account.
#[derive(Debug, Clone, Deserialize)]
pub struct AccountApplicationView {
    pub application_id: String,
    pub display_name: String,
    /// `ACTIVE` / `DISABLED`.
    pub status: String,
    /// `EVERYONE` / `INDIVIDUAL`.
    pub assignment_mode: String,
    /// `allowed` / `not_assigned` / `application_disabled`.
    pub access: String,
    #[serde(default)]
    pub assigned_at: Option<String>,
}

/// Response of a password reissue by an admin (`POST /admin/users/{id}/password-reset` and others).
/// A one-time link to hand to the user is returned only once (ADR-0062).
///
#[derive(Debug, Clone, Deserialize)]
pub struct UserPasswordResetView {
    #[allow(dead_code)]
    pub user_id: String,
    pub setup_url: String,
    pub setup_expires_at: String,
}

/// Result of an MFA reset by an admin (`POST /admin/users/{id}/mfa-reset`; MT21).
/// Only what was removed is returned (no secrets or credentials).
#[derive(Debug, Clone, Deserialize)]
pub struct UserMfaResetView {
    #[allow(dead_code)]
    pub user_id: String,
    pub totp_removed: bool,
    pub passkeys_removed: u64,
}

/// Result of a token reissue by an admin (`POST /admin/users/{id}/token-reissue`; ADR-0047).
/// `revoked` distinguishes "dropped" from "there was nothing to drop".
#[derive(Debug, Clone, Deserialize)]
pub struct UserTokenReissueView {
    #[allow(dead_code)]
    pub user_id: String,
    pub revoked: u64,
}

/// Number of the user's currently valid tokens (`GET /admin/users/{id}/active-tokens`; task #83).
/// Only refresh tokens can be counted (access tokens have no DB rows).
#[derive(Debug, Clone, Deserialize)]
pub struct UserActiveTokensView {
    #[allow(dead_code)]
    pub user_id: String,
    pub active_refresh_tokens: u64,
}

/// Result of an account unlock by an admin (`POST /admin/users/{id}/unlock`; AP6).
/// `was_locked` distinguishes "unlocked" from "was not locked in the first place".
#[derive(Debug, Clone, Deserialize)]
pub struct UserUnlockView {
    #[allow(dead_code)]
    pub user_id: String,
    pub was_locked: bool,
}

/// Invitation creation response (`POST /admin/invitations`). `token` is returned in plaintext only once (ADR-0009 §3).
#[derive(Debug, Clone, Deserialize)]
pub struct InvitationCreatedView {
    pub token: String,
    pub expires_at: String,
    /// Whether the invitation email (acceptance link) could be sent (MT17). If false, the token is conveyed manually.
    pub email_sent: bool,
    /// Invitee's email address (for confirming the destination). Present only when invited by email address (task #591).
    #[serde(default)]
    pub invitee_email: Option<String>,
}

/// Public representation of a tenant (response of `GET/PATCH /admin/settings/tenant`; MT14).
#[derive(Debug, Clone, Deserialize)]
pub struct TenantView {
    pub id: String,
    pub name: String,
    /// Whether self-registration (`/auth/register`) is allowed (SEC6; disabled by default).
    #[serde(default)]
    pub self_registration_enabled: bool,
    /// Whether login by email address is allowed (ADR-0050; disabled by default).
    #[serde(default)]
    pub email_login_enabled: bool,
    /// `ACTIVE` or `DISABLED`.
    pub status: String,
}

/// One page of the child tenant list (`GET /admin/tenants`; G7).
#[derive(Debug, Clone, Deserialize)]
pub struct TenantListView {
    pub tenants: Vec<TenantView>,
    /// Total count before paging.
    pub total: i64,
    /// Page size the api actually applied (after clamping).
    pub limit: i64,
    #[allow(dead_code)]
    pub offset: i64,
}

/// Tenant creation response (`POST /admin/tenants`). The creator becomes the bootstrap admin,
/// so no initial admin ID or plaintext password is included (the created tenant itself is returned; ADR-0009 §4).
#[derive(Debug, Clone, Deserialize)]
pub struct TenantCreatedView {
    pub id: String,
    #[serde(default)]
    pub parent_tenant_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub self_registration_enabled: bool,
    pub status: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

/// Public representation of system settings (response of `GET/PUT /admin/system-settings`; MT14).
/// The SMTP password is not included in plaintext; only whether it is set (`smtp_password_set`).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeSettingView {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub secret: bool,
    #[serde(default)]
    pub restart_required: bool,
    #[serde(default)]
    pub default_risk: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub reason: String,
    /// Description of what this setting is used for (for operators).
    #[serde(default)]
    pub description: String,
    /// Effective value resolved at startup (non-secret only). Doesn't change after a DB update until restart.
    #[serde(default)]
    pub value: Option<String>,
    /// Built-in default (non-secret only).
    #[serde(default)]
    pub default_value: Option<String>,
    /// Override value currently stored in the DB (non-secret only).
    #[serde(default)]
    pub db_value: Option<String>,
    /// Whether it can be overridden from this screen (DB) (`DB_MANAGED` and non-secret).
    #[serde(default)]
    pub editable: bool,
    /// Whether saved but not yet applied to the running api (MT27). Also `true` when removing an override is not yet applied.
    #[serde(default)]
    pub pending_restart: bool,
    /// Whether web consumes the key too (ADR-0013). Applying it requires restarting both the api and web.
    #[serde(default)]
    pub shared_with_web: bool,
    /// Whether tenants can override the key (ADR-0058).
    #[serde(default)]
    pub tenant_overridable: bool,
    /// Number of tenants following the global value (only for tenant-overridable keys).
    #[serde(default)]
    pub tenants_following: Option<u64>,
    /// Tenants deviating from the default (only for tenant-overridable keys).
    #[serde(default)]
    pub tenants_overriding: Vec<TenantOverrideView>,
}

/// One "tenant deviating from the default" shown on the global settings screen (ADR-0058 §6).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TenantOverrideView {
    pub tenant_id: String,
    pub tenant_name: String,
    pub value: String,
}

/// The tenant's own mail route (`GET/PUT/DELETE /admin/settings/smtp`; ADR-0058 §8).
///
/// When `inherited` is true, mail goes via the global route. ⚠ In that case the api returns the fields empty
/// (the global destination and username are not shown to tenants). For the password, only whether it is set.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TenantSmtpView {
    #[serde(default)]
    pub inherited: bool,
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: Option<u16>,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password_set: bool,
    #[serde(default)]
    pub smtp_from_address: String,
    #[serde(default)]
    pub smtp_use_tls: bool,
}

/// List of the tenant's setting values (`GET /admin/settings/tenant/keys`; ADR-0058).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TenantSettingsListView {
    #[serde(default)]
    pub settings: Vec<TenantSettingView>,
}

/// One tenant setting item. The order of items and the shape of inputs are decided from the definitions the api returns (web doesn't know the items).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TenantSettingView {
    pub key: String,
    #[serde(default)]
    pub description: String,
    /// `UNSIGNED_INTEGER` / `BOOLEAN` / `TEXT` / `PUBLIC_BASE_URL` / `CHOICE`.
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub choices: Vec<SettingChoiceView>,
    #[serde(default)]
    pub value: String,
    /// `TENANT_OVERRIDE` (decided in this tenant) / `INHERITED` (following the global value).
    #[serde(default)]
    pub origin: String,
    /// The global value (removing the override returns to this value).
    #[serde(default)]
    pub whole_idp_value: String,
}

impl TenantSettingView {
    /// Whether the value was decided in this tenant (`false` = following the global value).
    pub fn is_tenant_override(&self) -> bool {
        self.origin == "TENANT_OVERRIDE"
    }
}

/// One choice. Changing to a `locks_out` value inserts a confirmation before saving.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SettingChoiceView {
    pub value: String,
    #[serde(default)]
    pub locks_out: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SystemSettingsView {
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: Option<u16>,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password_set: bool,
    #[serde(default)]
    pub smtp_from_address: String,
    #[serde(default)]
    pub smtp_use_tls: bool,
    /// SMS gateway (AP13). The token is not included in plaintext; only whether it is set (`sms_auth_token_set`).
    #[serde(default)]
    pub sms_gateway_url: String,
    #[serde(default)]
    pub sms_auth_header: String,
    #[serde(default)]
    pub sms_auth_token_set: bool,
    #[serde(default)]
    pub sms_sender_id: String,
    #[serde(default)]
    pub runtime_settings: Vec<RuntimeSettingView>,
}

// ── External IdP settings (AP10's API turned into screens in AP16) ─────────────────────────────

/// One external IdP setting (`GET /admin/external-idps`).
///
/// The api doesn't return `client_secret` (stored encrypted; decrypted only at the moment of a token request to the external IdP).
/// The screen shows only "whether it is set" (`has_client_secret`).
///
/// Protocol-specific fields (OIDC endpoints, SAML SSO URL) are **`null` on the unused side** in the api
/// (ADR-0027). Without receiving them as `Option`, parsing the whole list would fail as soon as a single SAML provider
/// is registered, and the screen would not open.
#[derive(Debug, Clone, Deserialize)]
pub struct ExternalIdpView {
    pub id: String,
    pub provider_code: String,
    pub display_name: String,
    pub issuer: String,
    /// `oidc` / `saml`.
    #[serde(default = "oidc_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    pub has_client_secret: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// SAML only.
    #[serde(default)]
    pub saml_sso_url: Option<String>,
    #[serde(default)]
    pub saml_certificates: Vec<String>,
    #[serde(default)]
    pub saml_name_id_format: Option<String>,
    /// SAML only. assay's entityID and ACS URL to register with the external IdP.
    #[serde(default)]
    pub saml_sp_entity_id: Option<String>,
    #[serde(default)]
    pub saml_acs_url: Option<String>,
    pub enabled: bool,
    pub allow_auto_link: bool,
    /// Callback URL to register with the external IdP (a clue for the setup work).
    pub redirect_uri: String,
    #[allow(dead_code)]
    pub created_at: String,
    #[allow(dead_code)]
    pub updated_at: String,
}

fn oidc_protocol() -> String {
    "oidc".to_string()
}

impl ExternalIdpView {
    pub fn is_saml(&self) -> bool {
        self.protocol == "saml"
    }

    /// URL of the endpoint to have registered with the external IdP. `redirect_uri` for OIDC, ACS URL for SAML;
    /// shown in the same list column (for admins they play the same role, "the URL to paste on the other side").
    pub fn callback_url(&self) -> &str {
        match self.saml_acs_url.as_deref() {
            Some(acs) if self.is_saml() => acs,
            _ => &self.redirect_uri,
        }
    }
}

// ── Login identifiers (AP8's API turned into screens in AP16) ───────────────────────────

/// One login identifier of a user (`GET /admin/users/{id}/login-identifiers`).
#[derive(Debug, Clone, Deserialize)]
pub struct LoginIdentifierView {
    /// Registry row id. `None` is a row synthesized from the primary identifier (`users.preferred_username`),
    /// which is not stored, so per-identifier operations are not possible.
    pub id: Option<String>,
    pub identifier_type: String,
    /// The value as registered (for display).
    pub display_value: String,
    /// Match key (the value with per-type normalization applied). **Showing both** is the point: unless admins
    /// can compare "the registered value" with "the value that actually matches", they can't notice misconfigurations of
    /// identifiers whose notation varies, such as phone numbers.
    pub normalized_value: String,
    pub is_active: bool,
    pub is_primary: bool,
    /// Whether it is the primary email address row (ADR-0050). Not subject to individual enable/disable or deletion.
    #[serde(default)]
    pub is_primary_email: bool,
    #[allow(dead_code)]
    pub created_at: String,
    #[allow(dead_code)]
    pub updated_at: String,
}
