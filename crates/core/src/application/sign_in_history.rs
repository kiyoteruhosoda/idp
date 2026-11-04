//! 本人が見る「ログイン履歴」（task #879。ADR-0073）。
//!
//! # 何をどこで写すか
//!
//! | 出来事 | 写す所 |
//! |---|---|
//! | 成功したログイン | web がログイン状態の Cookie を置いた応答（`/internal/devices/observe`。端末の判定と同じ所） |
//! | 断ったログイン | 監査ログへ書く所（[`SignInFailureRecordingSink`]）。経路が 7 つあるので 1 か所で拾う |
//! | アプリへトークンを出した・更新した・使い回しを検知した | `TokenService`（`/token`） |
//!
//! 成功を web の応答で拾うのは、そこでしか国（`CF-IPCountry`）が分からないから。国は web が
//! `TRUST_FORWARDED_HEADERS` のときだけ読み、家の中からの通信では入口が消す（task #872 と同じ扱い）。
//!
//! # 本人だけ
//!
//! 履歴はログイン状態（SSO セッション）の持ち主のものしか返さない。利用者 id を外から受け取らない。

use crate::domain::audit::AuditEvent;
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::{
    AuditLogSink, SignInHistoryRepository, SsoSessionRepository, UserRepository,
};
use crate::domain::sign_in_history::{
    sign_in_failure_from_audit, SignInAppUse, SignInRecord, SignInSuccess, SIGN_IN_HISTORY_PAGE_MAX,
};
use crate::domain::sso_session;
use crate::domain::user_device::{CountryCode, OBSERVATION_WINDOW_SECS};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;

/// 履歴の 1 行と、成功したログインならそのアプリでの使われ方。
#[derive(Debug, Clone)]
pub struct SignInHistoryEntry {
    pub record: SignInRecord,
    pub apps: Vec<SignInAppUse>,
    /// 今見ているログイン状態そのものか。
    pub current: bool,
}

#[derive(Debug, Clone)]
pub struct SignInHistoryPage {
    pub entries: Vec<SignInHistoryEntry>,
    /// もっと古い行があれば、次のページを頼むときに渡す値。
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

    /// 作られたばかりのログイン状態を履歴へ写す。同じログインの 2 回目の頼みは何もしない。
    ///
    /// 古いログイン状態は写さない（端末の結び付けと同じ 2 分の窓。後から別の国を書かせない）。
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

    /// ログイン状態の持ち主の履歴を新しい順に返す。
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
        // 1 行多く引いて、次のページがあるかを決める。
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

/// 監査ログへ書くついでに、断ったログインを本人の履歴へ写す（[`AuditLogSink`] を包む）。
///
/// ログインの経路（パスワード・確認コード・パスキー・外部 IdP・管理コンソール・パスワード変更）は
/// どれも監査ログへ `login.failed` 等を書く。経路ごとに写しを足すと漏れるので、書き込みの口で拾う。
/// 写しに失敗しても監査ログの書き込みは成否を変えない。
pub struct SignInFailureRecordingSink {
    inner: Arc<dyn AuditLogSink>,
    history: Arc<dyn SignInHistoryRepository>,
}

impl SignInFailureRecordingSink {
    pub fn new(inner: Arc<dyn AuditLogSink>, history: Arc<dyn SignInHistoryRepository>) -> Self {
        Self { inner, history }
    }
}

#[async_trait]
impl AuditLogSink for SignInFailureRecordingSink {
    async fn record(&self, event: &AuditEvent) -> Result<()> {
        let result = self.inner.record(event).await;
        if let Some(failure) = sign_in_failure_from_audit(event) {
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

/// 履歴の写しの失敗はログに残して続ける（トークンの発行を止めない）。
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
        let sink = SignInFailureRecordingSink::new(Arc::new(FailingAudit), history.clone());
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
    }
}
