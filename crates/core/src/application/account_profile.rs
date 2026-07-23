//! ユーザーのセルフサービス・プロフィール（表示名）ユースケース。
//!
//! ログイン済みユーザーが SSO セッション経由で自分の `users.name`（表示名）を取得・更新する。
//! 表示名は一意制約・書式制約を持たない自由入力で、空・空白のみは解除（`NULL`）に正規化する。

use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::repositories::{SsoSessionRepository, UserRepository};
use crate::domain::user::User;
use crate::domain::values::validate_display_name;
use std::sync::Arc;

/// プロフィール取得結果（設定画面のプリフィル用）。
pub enum ProfileOutcome {
    Ok {
        name: Option<String>,
        preferred_username: Option<String>,
        email: String,
    },
    /// SSO セッションが無い・期限切れ。
    SessionExpired,
    Internal(String),
}

pub struct UpdateNameCommand {
    /// SSO セッション Cookie の生値（SHA-256 ハッシュで DB 検索する）。
    pub sso_session_id: String,
    /// 新しい表示名。空・空白のみ・`None` は解除扱い（DB `NULL`）。
    pub name: Option<String>,
}

pub enum UpdateNameOutcome {
    Ok,
    /// SSO セッションが無い・期限切れ。
    SessionExpired,
    /// 表示名が長すぎる等、値が不正。
    Invalid,
    Internal(String),
}

pub struct AccountProfileService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    clock: Arc<dyn Clock>,
}

impl AccountProfileService {
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            clock,
        }
    }

    /// 現在のプロフィール（表示名・ログイン識別子・メール）を取得する。
    pub async fn get(&self, sso_session_id: &str) -> ProfileOutcome {
        match self.resolve_active_user(sso_session_id).await {
            Ok(Some(user)) => ProfileOutcome::Ok {
                name: user.name,
                preferred_username: user.preferred_username,
                email: user.email,
            },
            Ok(None) => ProfileOutcome::SessionExpired,
            Err(e) => ProfileOutcome::Internal(e),
        }
    }

    /// 表示名を更新する（空・空白のみは解除）。
    pub async fn update_name(&self, cmd: UpdateNameCommand) -> UpdateNameOutcome {
        // 空・空白のみは解除（`NULL`）へ正規化。前後の空白はトリムして保存する。
        let normalized = cmd
            .name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        if let Some(ref name) = normalized {
            if validate_display_name(name).is_err() {
                return UpdateNameOutcome::Invalid;
            }
        }

        let user = match self.resolve_active_user(&cmd.sso_session_id).await {
            Ok(Some(user)) => user,
            Ok(None) => return UpdateNameOutcome::SessionExpired,
            Err(e) => return UpdateNameOutcome::Internal(e),
        };

        if let Err(e) = self.users.update_name(user.id, normalized.as_deref()).await {
            return UpdateNameOutcome::Internal(e.to_string());
        }
        UpdateNameOutcome::Ok
    }

    /// SSO セッションから本人を解決し、**有効なユーザー行**を返す。セッション無効・ユーザー不在・
    /// 無効化済み（LOCKED/DISABLED）はいずれも `Ok(None)`（未ログイン扱い）。他の認証済み経路
    /// （`AdminAccessService` / `AccountPasswordService`）と同様に `is_active()` を必須とし、
    /// セッションが残存する無効アカウントによる操作を防ぐ。
    async fn resolve_active_user(&self, sso_session_id: &str) -> Result<Option<User>, String> {
        let now = self.clock.now();
        let session_hash = crypto::sha256_hex(sso_session_id);
        let user_id = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s.user_id,
            Ok(_) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        match self.users.find_by_id(user_id).await {
            Ok(Some(user)) if user.is_active() => Ok(Some(user)),
            Ok(_) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}
