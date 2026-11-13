//! Shared module for issuing authorization codes (used by design spec §4.2 / §4.3).
//!
//! A code is generated as a 256-bit cryptographic random value and only `SHA-256(code)` is stored in the DB.
//! On issuance, `authorization_code.issued` is recorded in the audit log.
//!
//! # This is also the gate for "may this user use the application" (ADR-0054)
//!
//! All seven paths — login, MFA, passkey, external IdP, password change, consent and SSO restore — end
//! up here
//! ——**this is the only path that can issue a code**. So the check lives here too. Copying the check
//! into each authentication path means every new path that forgets it opens the gate as-is.

use crate::application::application_access::{ApplicationAccessService, ApplicationGate};
use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session::Authentication;
use crate::domain::authorization_code::AuthorizationCode;
use crate::domain::authorization_request::AuthorizationRequest;
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::repositories::AuthorizationCodeRepository;
use crate::domain::tenant_context::TenantContext;
use chrono::Duration;
use std::sync::Arc;

/// Authorization data needed to issue a code: **which authorization request** is answered **with which authentication**.
///
/// Both are carried over from the AuthSession (or SSO restore). The authorization request is as accepted
/// at `/authorize`; the authentication is the source of the ID Token's `sub` / `auth_time` / `sid` / `acr` / `amr`.
pub struct IssueCodeCommand {
    /// The tenant that issues the code (the flow's tenant).
    pub tenant: TenantContext,
    pub request: AuthorizationRequest,
    pub authentication: Authentication,
}

/// Result of issuing a code.
///
/// "Denied" is not an `Err` because **callers handle them differently**. An `Err` is a failure returned
/// to the RP as `server_error`, while an assignment denial is shown on assay's screen (ADR-0054 decision 2).
/// Mixing them in one type means a mix-up on either path changes what the user sees.
pub enum CodeIssuance {
    /// Issued (plaintext code; the caller appends it to `redirect_uri`).
    Issued(String),
    /// Use of this application is not permitted. ⚠ **Do not return to the RP.**
    ApplicationDenied {
        /// Application name shown on screen. Without knowing "which application refused me", the user
        /// cannot decide what to do next (whom to ask).
        application_name: String,
    },
}

pub struct CodeIssuanceService {
    codes: Arc<dyn AuthorizationCodeRepository>,
    applications: Arc<ApplicationAccessService>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ttl: Duration,
}

impl CodeIssuanceService {
    pub fn new(
        codes: Arc<dyn AuthorizationCodeRepository>,
        applications: Arc<ApplicationAccessService>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ttl: std::time::Duration,
    ) -> Self {
        Self {
            codes,
            applications,
            audit,
            clock,
            ttl: Duration::from_std(ttl).expect("authorization code TTL out of range"),
        }
    }

    /// Issues an authorization code.
    ///
    /// The check (ADR-0054) runs **before the write**. If placed after, a denial leaves an unused code
    /// in the DB.
    pub async fn issue(
        &self,
        cmd: IssueCodeCommand,
        ctx: &RequestContext,
    ) -> Result<CodeIssuance, DomainError> {
        if let ApplicationGate::Denied {
            application_name, ..
        } = self
            .applications
            .check(
                cmd.tenant.tenant_id(),
                cmd.request.client_id(),
                cmd.authentication.user_id(),
                ctx,
            )
            .await
        {
            return Ok(CodeIssuance::ApplicationDenied { application_name });
        }

        let IssueCodeCommand {
            tenant,
            request,
            authentication,
        } = cmd;
        let user_id = authentication.user_id();
        let (record, code) = AuthorizationCode::issue(
            tenant.tenant_id(),
            &request,
            authentication,
            self.clock.now(),
            self.ttl,
        );

        self.codes.create(&record).await?;

        self.audit
            .record(
                AuditEventType::AuthorizationCodeIssued,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(user_id),
                Some(request.client_id()),
                None,
                ctx,
            )
            .await;

        Ok(CodeIssuance::Issued(code.into_string()))
    }
}
