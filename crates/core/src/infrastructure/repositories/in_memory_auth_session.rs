//! `AuthSessionRepository` のメモリ上の実装（Application 層の単体試験用）。
//!
//! 書き込みは sqlx 実装の UPDATE と同じ規則で行う: 変更に含まれる**旧い id の行**を探し、
//! 記録された列だけを書き換えて新しい id に付け替える。旧い id の行が無ければ何もしない
//! （UPDATE が 0 行に当たったのと同じ）。

use crate::domain::auth_session::{
    AuthSession, AuthSessionIdHash, AuthSessionParts, AuthenticationCompletion, HandoffExchange,
    HandoffHandleHash, PasswordVerification,
};
use crate::domain::error::Result;
use crate::domain::repositories::AuthSessionRepository;
use crate::domain::tenant::TenantId;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Mutex;

#[derive(Default)]
pub struct InMemoryAuthSessions {
    rows: Mutex<Vec<AuthSession>>,
}

impl InMemoryAuthSessions {
    pub fn with(sessions: Vec<AuthSession>) -> Self {
        Self {
            rows: Mutex::new(sessions),
        }
    }

    /// 保存されている行の写し（試験の検証用）。
    pub fn rows(&self) -> Vec<AuthSession> {
        self.rows.lock().unwrap().clone()
    }

    /// `previous` の行を `rewrite` で書き換える。行が無ければ `false`。
    fn rewrite(
        &self,
        previous: &AuthSessionIdHash,
        rewrite: impl FnOnce(&mut AuthSessionParts),
    ) -> bool {
        let mut rows = self.rows.lock().unwrap();
        let Some(row) = rows.iter_mut().find(|s| s.id_hash() == previous) else {
            return false;
        };
        let mut parts = row.to_parts();
        rewrite(&mut parts);
        *row = AuthSession::reconstitute(parts);
        true
    }
}

#[async_trait]
impl AuthSessionRepository for InMemoryAuthSessions {
    async fn create(&self, session: &AuthSession) -> Result<()> {
        self.rows.lock().unwrap().push(session.clone());
        Ok(())
    }

    async fn find(
        &self,
        tenant_id: TenantId,
        id: &AuthSessionIdHash,
    ) -> Result<Option<AuthSession>> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.tenant_id() == tenant_id && s.id_hash() == id)
            .cloned())
    }

    async fn find_by_handoff(
        &self,
        tenant_id: TenantId,
        handle: &HandoffHandleHash,
    ) -> Result<Option<AuthSession>> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .find(|s| {
                s.tenant_id() == tenant_id && s.handoff().map(|h| h.handle_hash()) == Some(handle)
            })
            .cloned())
    }

    async fn save_handoff_exchange(&self, exchange: &HandoffExchange) -> Result<bool> {
        let rotation = exchange.rotation();
        let still_unconsumed = self.rows.lock().unwrap().iter().any(|s| {
            s.id_hash() == rotation.previous()
                && s.handoff().map(|h| h.handle_hash()) == Some(exchange.consumed())
        });
        if !still_unconsumed {
            return Ok(false);
        }
        Ok(self.rewrite(rotation.previous(), |row| {
            row.id_hash = rotation.issued_hash();
            row.handle_hash = None;
            row.handle_expires_at = None;
        }))
    }

    async fn save_password_verification(&self, verification: &PasswordVerification) -> Result<()> {
        let rotation = verification.rotation();
        self.rewrite(rotation.previous(), |row| {
            row.id_hash = rotation.issued_hash();
            row.authenticated_user_id = Some(verification.user_id());
            row.password_verified_at = Some(verification.verified_at());
            row.auth_time = None;
            row.sso_sid = None;
            row.authentication_methods = None;
        });
        Ok(())
    }

    async fn save_authentication(&self, completion: &AuthenticationCompletion) -> Result<()> {
        let rotation = completion.rotation();
        let authentication = completion.authentication();
        self.rewrite(rotation.previous(), |row| {
            row.id_hash = rotation.issued_hash();
            row.authenticated_user_id = Some(authentication.user_id());
            row.auth_time = Some(authentication.auth_time());
            row.sso_sid = authentication.sso_sid().map(str::to_string);
            row.authentication_methods = authentication.methods().map(<[_]>::to_vec);
        });
        Ok(())
    }

    async fn delete(&self, id: &AuthSessionIdHash) -> Result<()> {
        self.rows.lock().unwrap().retain(|s| s.id_hash() != id);
        Ok(())
    }

    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<u64> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|s| !s.is_expired_at(now));
        Ok((before - rows.len()) as u64)
    }
}
