//! Entry point for evaluating authentication policies (user authentication & authentication policy spec §9, AP2/AP3, ADR-0054 decision 5).
//!
//! The evaluation itself is done by a pure domain function ([`evaluate_policies`]). This module only
//! owns the steps that gather its inputs:
//!
//! 1. Target translation —— the flow only has a `client_id`, so it is translated to an application
//!    (a policy's `conditions.application_ids` points at applications). A client not yet linked to
//!    an application is `None`, and policies with `application_ids` do not match it
//! 2. The default effect when no policy matches (the tenant's value, looked up every time. ADR-0058 §4)
//! 3. The tenant's enabled policies
//!
//! Eight paths — login, MFA, passkey, password change, external IdP, SSO restore, admin console and
//! portal — each copied the same steps; they were gathered here. How to handle the conclusion (`PolicyDecision`)
//! (how to audit a denial, whether to require a second factor) differs per path, so it stays with the caller.

use crate::application::application_access::ApplicationAccessService;
use crate::domain::authentication_policy::{
    evaluate_policies, AuthenticationContext, PolicyDecision,
};
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::DomainError;
use crate::domain::repositories::AuthenticationPolicyRepository;
use crate::domain::tenant::TenantId;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// The target of a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAudience<'a> {
    /// The client that sent the OIDC authorization request (evaluated after translating it to an application).
    OidcClient(&'a str),
    /// Outside an authorization request (external IdP linking started from the admin console, portal or account settings).
    /// There is no target, so policies with `application_ids` do not match.
    Unaddressed,
}

/// The question to evaluate: who, to where, from where, and when.
#[derive(Debug, Clone, Copy)]
pub struct PolicyQuery<'a> {
    pub tenant_id: TenantId,
    pub audience: PolicyAudience<'a>,
    pub user_id: Uuid,
    pub ip_address: Option<&'a str>,
    /// `acr_values` of the authorization request (used by AP3's `requested_acr` condition). Empty outside an authorization request.
    pub requested_acr: &'a [String],
    pub now: DateTime<Utc>,
}

pub struct AuthenticationPolicyGate {
    policies: Arc<dyn AuthenticationPolicyRepository>,
    settings: Arc<dyn EffectiveTenantSettings>,
    applications: Arc<ApplicationAccessService>,
}

impl AuthenticationPolicyGate {
    pub fn new(
        policies: Arc<dyn AuthenticationPolicyRepository>,
        settings: Arc<dyn EffectiveTenantSettings>,
        applications: Arc<ApplicationAccessService>,
    ) -> Self {
        Self {
            policies,
            settings,
            applications,
        }
    }

    /// Reaches a conclusion for the question. `Err` if any input cannot be looked up (the caller treats it as an internal error).
    pub async fn decide(&self, query: PolicyQuery<'_>) -> Result<PolicyDecision, DomainError> {
        let application_id = match query.audience {
            PolicyAudience::OidcClient(client_id) => {
                self.applications
                    .policy_target_for_oidc_client(query.tenant_id, client_id)
                    .await?
            }
            PolicyAudience::Unaddressed => None,
        };
        let default_effect = self.settings.policy_default_effect(query.tenant_id).await?;
        let policies = self
            .policies
            .list_enabled_for_tenant(query.tenant_id)
            .await?;
        Ok(evaluate_policies(
            &policies,
            &AuthenticationContext {
                application_id,
                user_id: query.user_id,
                ip_address: query.ip_address,
                now: query.now,
                requested_acr: query.requested_acr,
            },
            default_effect,
        ))
    }
}

/// Test helper that builds the evaluation entry point (every application lookup yields "no application").
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::application::audit::AuditService;

    pub fn gate(
        policies: Arc<dyn AuthenticationPolicyRepository>,
        settings: Arc<dyn EffectiveTenantSettings>,
        audit: Arc<AuditService>,
    ) -> Arc<AuthenticationPolicyGate> {
        Arc::new(AuthenticationPolicyGate::new(
            policies,
            settings,
            crate::application::application_access::test_support::allow_everything(audit),
        ))
    }
}
