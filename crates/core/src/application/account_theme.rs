//! ユーザーの配色設定更新ユースケース。
//!
//! ログイン済みユーザーが SSO セッション経由で自分の `theme` 列（`light` / `dark` / `system`）を
//! 更新する。DB への書き込みのみで、実際の配色の適用は web（`data-bs-theme`）が行う。
//!
//! `system`（OS に合わせる）を `NULL`（未設定）と別の値として持つのは、前者が**利用者の選択**
//! だからである。未設定なら端末に残った Cookie を尊重してよいが、`system` を選んだ利用者の
//! 画面は端末をまたいで OS 追従であるべきで、この 2 つを同じ値にすると区別が付かない。

use crate::domain::crypto;
use crate::domain::repositories::{SsoSessionRepository, UserRepository};
use std::sync::Arc;

/// 許可する配色設定の値（DB の CHECK 制約と一致させる）。
const ALLOWED_THEMES: [&str; 3] = ["light", "dark", "system"];

pub struct UpdateThemeCommand {
    /// SSO セッション Cookie の生値（SHA-256 ハッシュで DB 検索する）。
    pub sso_session_id: String,
    /// 設定する配色（`light` / `dark` / `system`）。不正値は Validation エラー。
    pub theme: String,
}

pub enum UpdateThemeOutcome {
    Ok,
    /// SSO セッションが無い・期限切れ。
    SessionExpired,
    /// 配色の値が非対応。
    InvalidTheme,
    Internal(String),
}

pub struct AccountThemeService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    clock: Arc<dyn crate::domain::clock::Clock>,
}

impl AccountThemeService {
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        clock: Arc<dyn crate::domain::clock::Clock>,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            clock,
        }
    }

    pub async fn update(&self, cmd: UpdateThemeCommand) -> UpdateThemeOutcome {
        let theme = cmd.theme.trim();
        if !ALLOWED_THEMES.contains(&theme) {
            return UpdateThemeOutcome::InvalidTheme;
        }
        let theme = theme.to_string();

        let now = self.clock.now();

        // SSO セッションから本人を解決する。
        let session_hash = crypto::sha256_hex(&cmd.sso_session_id);
        let session = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s,
            Ok(_) => return UpdateThemeOutcome::SessionExpired,
            Err(e) => return UpdateThemeOutcome::Internal(e.to_string()),
        };

        if let Err(e) = self.users.update_theme(session.user_id, Some(&theme)).await {
            return UpdateThemeOutcome::Internal(e.to_string());
        }

        UpdateThemeOutcome::Ok
    }
}
