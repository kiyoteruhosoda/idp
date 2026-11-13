//! The "sign-in history" the user sees (task #879. ADR-0073).
//!
//! # What is recorded where
//!
//! | Event | Recorded at |
//! |---|---|
//! | Successful sign-in | The web response that set the signed-in Cookie (`/internal/devices/observe`. Same place as the device check) |
//! | Rejected sign-in | Where the audit log is written ([`SignInFailureRecordingSink`]). There are 7 paths, so it is caught in one place |
//! | Issued, refreshed a token to an app, or detected reuse | `TokenService` (`/token`) |
//!
//! Successes are caught from the web response because only there is the country (`CF-IPCountry`) known. The web reads the country
//! only with `TRUST_FORWARDED_HEADERS`, and the entrance strips it for traffic from inside the home (same handling as task #872).
//!
//! # Only the user themselves
//!
//! The history returned is only that of the owner of the signed-in state (SSO session). No user id is accepted from outside.

use crate::domain::audit::AuditEvent;
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::{
    AuditLogSink, SignInHistoryRepository, SsoSessionRepository, UserRepository,
};
use crate::domain::sign_in_history::{
    sign_in_failure_from_audit, RequestCountry, SignInAppUse, SignInRecord, SignInSuccess,
    SIGN_IN_HISTORY_PAGE_MAX,
};
use crate::domain::sso_session;
use crate::domain::user_device::{CountryCode, OBSERVATION_WINDOW_SECS};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;

/// One history row and, for a successful sign-in, how it was used by that app.
#[derive(Debug, Clone)]
pub struct SignInHistoryEntry {
    pub record: SignInRecord,
    pub apps: Vec<SignInAppUse>,
    /// Whether this is the very signed-in state currently being viewed.
    pub current: bool,
}

#[derive(Debug, Clone)]
pub struct SignInHistoryPage {
    pub entries: Vec<SignInHistoryEntry>,
    /// If there are older rows, the value to pass when requesting the next page.
    pub next_before: Option<i64>,
}

#[derive(Debug)]
pub enum SignInHistoryOutcome {
    Ok(SignInHistoryPage),
    SessionExpired,
    Internal(String),
}

pub struct SignInHistoryService {
    history: Arc<dyn SignInHistoryRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    clock: Arc<dyn Clock>,
}

impl SignInHistoryService {
    pub fn new(
        history: Arc<dyn SignInHistoryRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            history,
            sso_sessions,
            users,
            clock,
        }
    }

    /// Records a freshly created signed-in state into the history. A second request for the same sign-in does nothing.
    ///
    /// Old signed-in states are not recorded (same 2-minute window as device binding. Prevents writing a different country later).
    pub async fn record_sign_in(
        &self,
        sso_session_id: &str,
        country: Option<&str>,
        device_registered: Option<bool>,
    ) -> Result<bool> {
        let now = self.clock.now();
        let session_hash = crypto::sha256_hex(sso_session_id);
        let Some(session) = self.sso_sessions.find_by_hash(&session_hash).await? else {
            return Ok(false);
        };
        if !session.is_valid_at(now)
            || now - session.created_at > Duration::seconds(OBSERVATION_WINDOW_SECS)
        {
            return Ok(false);
        }
        let Some(user) = self.users.find_by_id(session.user_id).await? else {
            return Ok(false);
        };
        self.history
            .record_success(&SignInSuccess {
                user_id: user.id,
                tenant_id: user.tenant_id,
                occurred_at: session.auth_time,
                ip_address: session.ip_address.clone(),
                user_agent: session.user_agent.clone(),
                country: country.and_then(CountryCode::parse),
                methods: session.authentication_methods.clone(),
                sid: sso_session::sid_of(&session_hash),
                device_registered,
            })
            .await
    }

    /// Returns the history of the signed-in state's owner, newest first.
    pub async fn history(
        &self,
        sso_session_id: &str,
        before: Option<i64>,
        limit: u32,
    ) -> SignInHistoryOutcome {
        let now = self.clock.now();
        let session_hash = crypto::sha256_hex(sso_session_id);
        let session = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s,
            Ok(_) => return SignInHistoryOutcome::SessionExpired,
            Err(e) => return SignInHistoryOutcome::Internal(e.to_string()),
        };
        match self.users.find_by_id(session.user_id).await {
            Ok(Some(user)) if user.is_active() => {}
            Ok(_) => return SignInHistoryOutcome::SessionExpired,
            Err(e) => return SignInHistoryOutcome::Internal(e.to_string()),
        }
        match self
            .page(session.user_id, &session_hash, before, limit, now)
            .await
        {
            Ok(page) => SignInHistoryOutcome::Ok(page),
            Err(e) => SignInHistoryOutcome::Internal(e.to_string()),
        }
    }

    async fn page(
        &self,
        user_id: uuid::Uuid,
        session_hash: &str,
        before: Option<i64>,
        limit: u32,
        now: DateTime<Utc>,
    ) -> Result<SignInHistoryPage> {
        let limit = limit.clamp(1, SIGN_IN_HISTORY_PAGE_MAX);
        // Fetch one extra row to decide whether there is a next page.
        let mut records = self
            .history
            .list_for_user(user_id, before, limit + 1)
            .await?;
        let more = records.len() > limit as usize;
        records.truncate(limit as usize);
        let sids: Vec<String> = records.iter().filter_map(|r| r.sid.clone()).collect();
        let usage = self.history.app_usage(user_id, &sids, now).await?;
        let current_sid = sso_session::sid_of(session_hash);
        let next_before = if more {
            records.last().map(|r| r.id)
        } else {
            None
        };
        let entries = records
            .into_iter()
            .map(|record| {
                let apps = match &record.sid {
                    Some(sid) => usage.iter().filter(|u| &u.sid == sid).cloned().collect(),
                    None => Vec::new(),
                };
                SignInHistoryEntry {
                    current: record.sid.as_deref() == Some(current_sid.as_str()),
                    record,
                    apps,
                }
            })
            .collect();
        Ok(SignInHistoryPage {
            entries,
            next_before,
        })
    }
}

/// While writing to the audit log, also records rejected sign-ins into the user's history (wraps [`AuditLogSink`]).
///
/// Every sign-in path (password, verification code, passkey, external IdP, admin console, password change)
/// writes `login.failed` etc. to the audit log. Adding a copy per path would miss some, so it is caught at the write point.
/// A failure to copy does not change whether the audit log write succeeds.
pub struct SignInFailureRecordingSink {
    inner: Arc<dyn AuditLogSink>,
    history: Arc<dyn SignInHistoryRepository>,
    /// The current request's country (task #895). Audit events have no country, so it is added from here when copying.
    country: Arc<dyn RequestCountry>,
}

impl SignInFailureRecordingSink {
    pub fn new(
        inner: Arc<dyn AuditLogSink>,
        history: Arc<dyn SignInHistoryRepository>,
        country: Arc<dyn RequestCountry>,
    ) -> Self {
        Self {
            inner,
            history,
            country,
        }
    }
}

#[async_trait]
impl AuditLogSink for SignInFailureRecordingSink {
    async fn record(&self, event: &AuditEvent) -> Result<()> {
        let result = self.inner.record(event).await;
        if let Some(mut failure) = sign_in_failure_from_audit(event) {
            failure.country = self.country.current();
            if let Err(e) = self.history.record_failure(&failure).await {
                tracing::error!(error = %e, "failed to copy a failed sign-in into the sign-in history");
            }
        }
        result
    }

    async fn purge_older_than(&self, older_than: DateTime<Utc>) -> Result<u64> {
        self.inner.purge_older_than(older_than).await
    }
}

/// A failure to copy to the history is logged and processing continues (token issuance is not stopped).
pub fn log_history_error(result: std::result::Result<(), DomainError>, what: &'static str) {
    if let Err(e) = result {
        tracing::error!(error = %e, what, "failed to update the sign-in history");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::{AuditEventType, AuditResult};
    use crate::domain::sign_in_history::{SignInFailure, SignInOutcome};
    use crate::domain::tenant::TenantId;
    use std::sync::Mutex;
    use uuid::Uuid;

    #[derive(Default)]
    struct Recorded {
        failures: Mutex<Vec<SignInFailure>>,
    }

    #[async_trait]
    impl SignInHistoryRepository for Recorded {
        async fn record_success(&self, _: &SignInSuccess) -> Result<bool> {
            Ok(true)
        }
        async fn record_failure(&self, f: &SignInFailure) -> Result<()> {
            self.failures.lock().unwrap().push(f.clone());
            Ok(())
        }
        async fn record_app_issue(
            &self,
            _: Uuid,
            _: TenantId,
            _: &str,
            _: &str,
            _: DateTime<Utc>,
            _: bool,
        ) -> Result<()> {
            Ok(())
        }
        async fn record_refresh_use(
            &self,
            _: &str,
            _: &str,
            _: DateTime<Utc>,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<()> {
            Ok(())
        }
        async fn record_refresh_reuse(&self, _: &str, _: &str, _: DateTime<Utc>) -> Result<()> {
            Ok(())
        }
        async fn list_for_user(
            &self,
            _: Uuid,
            _: Option<i64>,
            _: u32,
        ) -> Result<Vec<SignInRecord>> {
            Ok(Vec::new())
        }
        async fn app_usage(
            &self,
            _: Uuid,
            _: &[String],
            _: DateTime<Utc>,
        ) -> Result<Vec<SignInAppUse>> {
            Ok(Vec::new())
        }
    }

    struct FailingAudit;

    #[async_trait]
    impl AuditLogSink for FailingAudit {
        async fn record(&self, _: &AuditEvent) -> Result<()> {
            Err(DomainError::Repository("down".into()))
        }
    }

    fn event(event_type: AuditEventType) -> AuditEvent {
        AuditEvent {
            event_type,
            occurred_at: DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            tenant_id: None,
            user_id: Some(Uuid::nil()),
            client_id: None,
            ip_address: Some("198.51.100.7".into()),
            user_agent: None,
            result: AuditResult::Failure,
            reason: Some("invalid_password".into()),
            correlation_id: "c".into(),
        }
    }

    #[tokio::test]
    async fn failed_sign_ins_are_copied_even_when_the_audit_write_fails() {
        let history = Arc::new(Recorded::default());
        let sink = SignInFailureRecordingSink::new(
            Arc::new(FailingAudit),
            history.clone(),
            Arc::new(FixedCountry),
        );
        assert!(
            sink.record(&event(AuditEventType::LoginFailed))
                .await
                .is_err(),
            "the audit result is passed through"
        );
        sink.record(&event(AuditEventType::TokenIssued)).await.ok();
        let copied = history.failures.lock().unwrap().clone();
        assert_eq!(copied.len(), 1, "only the failed sign-in is copied");
        assert_eq!(copied[0].outcome, SignInOutcome::Failed);
        assert_eq!(copied[0].ip_address.as_deref(), Some("198.51.100.7"));
        assert_eq!(
            copied[0].country.as_ref().map(CountryCode::as_str),
            Some("JP"),
            "the request's country is attached to the copy (task #895)"
        );
    }

    struct FixedCountry;

    impl RequestCountry for FixedCountry {
        fn current(&self) -> Option<CountryCode> {
            CountryCode::parse("JP")
        }
    }
}
