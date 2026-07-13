//! セルフサービスのパスワード変更ユースケース（ログイン済みユーザーの設定画面。MT15）。
//!
//! ログインフロー中の強制変更（[`crate::application::change_password`]、`auth_session` ベース）とは別に、
//! **SSO セッションを持つログイン済みユーザー**が自分の意思でパスワードを変更する経路を提供する。
//! SSO セッション Cookie から本人を解決し、現行パスワードを再検証したうえで新パスワードを設定する。
//! OIDC フローの一部ではないため code 再発行や redirect は行わない（成功後は設定画面に留まる）。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::password::{validate_password_strength, PasswordHasher};
use crate::domain::repositories::{SsoSessionRepository, UserRepository};
use crate::infrastructure::crypto;
use std::sync::Arc;

pub struct AccountPasswordCommand {
    /// SSO セッション Cookie の生値（SHA-256 ハッシュで DB 検索する）。
    pub sso_session_id: String,
    pub current_password: String,
    pub new_password: String,
}

pub enum AccountPasswordOutcome {
    Ok,
    /// SSO セッションが無い・期限切れ（未ログイン扱い）。
    SessionExpired,
    /// 現行パスワードが不一致。
    InvalidCurrentPassword,
    /// 新パスワードが強度要件を満たさない。
    WeakPassword,
    Internal(String),
}

pub struct AccountPasswordService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    hasher: Arc<dyn PasswordHasher>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl AccountPasswordService {
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        hasher: Arc<dyn PasswordHasher>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            hasher,
            audit,
            clock,
        }
    }

    pub async fn change(
        &self,
        cmd: AccountPasswordCommand,
        ctx: &RequestContext,
    ) -> AccountPasswordOutcome {
        let now = self.clock.now();

        // 1. SSO セッションから本人を解決する（有効期限も確認）。
        let session_hash = crypto::sha256_hex(&cmd.sso_session_id);
        let session = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s,
            Ok(_) => return AccountPasswordOutcome::SessionExpired,
            Err(e) => return AccountPasswordOutcome::Internal(e.to_string()),
        };
        let user = match self.users.find_by_id(session.user_id).await {
            Ok(Some(u)) if u.is_active() => u,
            Ok(_) => return AccountPasswordOutcome::SessionExpired,
            Err(e) => return AccountPasswordOutcome::Internal(e.to_string()),
        };

        // 2. 現行パスワードを再検証する。
        let verified = match self
            .hasher
            .verify(&cmd.current_password, &user.password_hash)
        {
            Ok(v) => v,
            Err(e) => return AccountPasswordOutcome::Internal(e.to_string()),
        };
        if !verified {
            return AccountPasswordOutcome::InvalidCurrentPassword;
        }

        // 3. 新パスワードの強度を検証し、ハッシュ化して保存する。
        if validate_password_strength(&cmd.new_password).is_err() {
            return AccountPasswordOutcome::WeakPassword;
        }
        let new_hash = match self.hasher.hash(&cmd.new_password) {
            Ok(h) => h,
            Err(e) => return AccountPasswordOutcome::Internal(e.to_string()),
        };
        if let Err(e) = self.users.update_password(user.id, &new_hash).await {
            return AccountPasswordOutcome::Internal(e.to_string());
        }

        self.audit
            .record(
                AuditEventType::PasswordChanged,
                AuditResult::Success,
                Some(user.tenant_id),
                Some(user.id),
                None,
                None,
                ctx,
            )
            .await;

        AccountPasswordOutcome::Ok
    }
}
