//! ユーザーの表示言語設定更新ユースケース（MT20）。
//!
//! ログイン済みユーザーが SSO セッション経由で自分の `language` 列（`ja` / `en` / `NULL`）を
//! 更新する。DB への書き込みのみで、i18n の適用はリクエストごとに `Accept-Language` で行う。

use crate::domain::repositories::{SsoSessionRepository, UserRepository};
use crate::infrastructure::crypto;
use std::sync::Arc;

pub struct UpdateLanguageCommand {
    /// SSO セッション Cookie の生値（SHA-256 ハッシュで DB 検索する）。
    pub sso_session_id: String,
    /// 設定する言語コード（`ja` / `en`）。不正値は Validation エラー。
    pub language: String,
}

pub enum UpdateLanguageOutcome {
    Ok,
    /// SSO セッションが無い・期限切れ。
    SessionExpired,
    /// 言語コードが非対応（`ja`・`en` 以外）。
    InvalidLanguage,
    Internal(String),
}

pub struct AccountLanguageService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    clock: Arc<dyn crate::domain::clock::Clock>,
}

impl AccountLanguageService {
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

    pub async fn update(&self, cmd: UpdateLanguageCommand) -> UpdateLanguageOutcome {
        // 対応言語の検証（ja / en のみ）。
        let lang = match cmd.language.trim() {
            "ja" | "en" => cmd.language.trim().to_string(),
            _ => return UpdateLanguageOutcome::InvalidLanguage,
        };

        let now = self.clock.now();

        // SSO セッションから本人を解決する。
        let session_hash = crypto::sha256_hex(&cmd.sso_session_id);
        let session = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s,
            Ok(_) => return UpdateLanguageOutcome::SessionExpired,
            Err(e) => return UpdateLanguageOutcome::Internal(e.to_string()),
        };

        if let Err(e) = self
            .users
            .update_language(session.user_id, Some(&lang))
            .await
        {
            return UpdateLanguageOutcome::Internal(e.to_string());
        }

        UpdateLanguageOutcome::Ok
    }
}
