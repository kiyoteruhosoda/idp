//! 期限切れ行の掃除（G2）を 1 ファイルに集約する。
//!
//! 進行状態・使い捨てトークンの表は放っておくと無限に増える。以前は `log` テーブルだけが定期削除の
//! 対象で、他は誰も消していなかった（`passkey_challenges` は `delete_expired` を実装しながら
//! 呼び出し元が無いままだった）。`revoked_access_tokens` は `/introspect` のブラックリスト照合に
//! 使うため、肥大がそのままレイテンシになる。
//!
//! 表ごとにバックグラウンドループを生やすと追加のたびに掃除漏れが生まれるので、
//! [`ExpiringRecordStore`] という 1 つのポートで「掃除できること」を表明し、
//! [`crate::application::expired_record_purge::ExpiredRecordPurgeService`] が 1 本のタスクで回す。
//!
//! **このファイルが GC の対象一覧である。** 期限を持つ表を足したら、ここに実装を足して
//! `all_expiring_record_stores` と `PURGED_TABLES` へ載せる（載せ忘れは統合テスト
//! `expired_record_purge::every_table_with_an_expiry_column_is_swept` が検出する）。

use crate::domain::error::Result;
use crate::domain::repositories::{
    AuthSessionRepository, ExpiringRecordStore, ExternalLoginRequestRepository,
    PasskeyChallengeRepository, SamlSsoRequestRepository, SsoSessionRepository,
    UserAuthenticatorRepository,
};
use crate::infrastructure::db::Db;
use crate::infrastructure::repositories::{
    auth_session::SqlxAuthSessionRepository, authorization_code::SqlxAuthorizationCodeRepository,
    client_assertion::SqlxClientAssertionReplayRepository,
    email_verification_token::SqlxEmailVerificationTokenRepository,
    external_idp::SqlxExternalLoginRequestRepository,
    passkey_challenge::SqlxPasskeyChallengeRepository,
    password_reset_token::SqlxPasswordResetTokenRepository,
    refresh_token::SqlxRefreshTokenRepository,
    revoked_access_token::SqlxRevokedAccessTokenRepository,
    saml_sso_request::SqlxSamlSsoRequestRepository, sso_session::SqlxSsoSessionRepository,
    user_authenticator::SqlxUserAuthenticatorRepository,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;

/// `expires_at <= now` の行を削除する共通実装（この GC の対象表はすべてこの形をしている）。
async fn delete_by_expires_at(pool: &Db, table: &str, now: DateTime<Utc>) -> Result<u64> {
    // テーブル名は本モジュール内の定数だけが渡る（外部入力を組み立てない）。
    let sql = format!("DELETE FROM {table} WHERE expires_at <= ?");
    let result = sqlx::query(&sql)
        .bind(now.naive_utc())
        .execute(pool)
        .await
        .map_err(|e| crate::domain::error::DomainError::Repository(e.to_string()))?;
    Ok(result.rows_affected())
}

/// 掃除対象を「所有するリポジトリのトレイトへ委譲する」形で表明するためのマクロ。
/// 既に `delete_expired` を持つリポジトリはそれを呼び、持たない表は直接 DELETE する。
macro_rules! purge_via_repository {
    ($ty:ty, $table:literal, $trait:path) => {
        #[async_trait]
        impl ExpiringRecordStore for $ty {
            fn table_name(&self) -> &'static str {
                $table
            }
            async fn purge_expired(&self, now: DateTime<Utc>) -> Result<u64> {
                <Self as $trait>::delete_expired(self, now).await
            }
        }
    };
}

purge_via_repository!(
    SqlxAuthSessionRepository,
    "auth_sessions",
    AuthSessionRepository
);
purge_via_repository!(
    SqlxSamlSsoRequestRepository,
    "saml_sso_requests",
    SamlSsoRequestRepository
);
purge_via_repository!(
    SqlxSsoSessionRepository,
    "sso_sessions",
    SsoSessionRepository
);
purge_via_repository!(
    SqlxPasskeyChallengeRepository,
    "passkey_challenges",
    PasskeyChallengeRepository
);
purge_via_repository!(
    SqlxExternalLoginRequestRepository,
    "external_login_requests",
    ExternalLoginRequestRepository
);
purge_via_repository!(
    SqlxUserAuthenticatorRepository,
    "user_authenticators",
    UserAuthenticatorRepository
);

/// 掃除しか用途の無い表（ユースケース側から期限切れ行を触ることが無い）は、
/// リポジトリトレイトを広げずにここで直接消す。
macro_rules! purge_directly {
    ($ty:ty, $table:literal) => {
        #[async_trait]
        impl ExpiringRecordStore for $ty {
            fn table_name(&self) -> &'static str {
                $table
            }
            async fn purge_expired(&self, now: DateTime<Utc>) -> Result<u64> {
                delete_by_expires_at(self.pool(), $table, now).await
            }
        }
    };
}

purge_directly!(SqlxAuthorizationCodeRepository, "authorization_codes");
purge_directly!(SqlxClientAssertionReplayRepository, "client_assertion_jtis");
purge_directly!(SqlxRefreshTokenRepository, "refresh_tokens");
purge_directly!(SqlxRevokedAccessTokenRepository, "revoked_access_tokens");
purge_directly!(SqlxPasswordResetTokenRepository, "password_reset_tokens");
purge_directly!(
    SqlxEmailVerificationTokenRepository,
    "email_verification_tokens"
);

/// 期限を持つ全テーブルの掃除口を組み立てる（**GC の対象一覧**）。
///
/// 起動時にここで作った一式を [`crate::application::expired_record_purge::ExpiredRecordPurgeService`]
/// へ渡す。表を足したときの追随漏れは統合テスト
/// `expired_record_purge::every_table_with_an_expiry_column_is_swept` が検出する。
pub fn all_expiring_record_stores(pool: Db) -> Vec<Arc<dyn ExpiringRecordStore>> {
    vec![
        Arc::new(SqlxAuthSessionRepository::new(pool.clone())),
        Arc::new(SqlxSamlSsoRequestRepository::new(pool.clone())),
        Arc::new(SqlxSsoSessionRepository::new(pool.clone())),
        Arc::new(SqlxPasskeyChallengeRepository::new(pool.clone())),
        Arc::new(SqlxExternalLoginRequestRepository::new(pool.clone())),
        Arc::new(SqlxUserAuthenticatorRepository::new(pool.clone())),
        Arc::new(SqlxAuthorizationCodeRepository::new(pool.clone())),
        Arc::new(SqlxClientAssertionReplayRepository::new(pool.clone())),
        Arc::new(SqlxRefreshTokenRepository::new(pool.clone())),
        Arc::new(SqlxRevokedAccessTokenRepository::new(pool.clone())),
        Arc::new(SqlxPasswordResetTokenRepository::new(pool.clone())),
        Arc::new(SqlxEmailVerificationTokenRepository::new(pool)),
    ]
}

/// GC が覆うべき表の名前（`all_expiring_record_stores` と対で保守する）。
/// 統合テストが `information_schema` と突き合わせ、`expires_at` を持つのに載っていない表を検出する。
pub const PURGED_TABLES: &[&str] = &[
    "auth_sessions",
    "saml_sso_requests",
    "sso_sessions",
    "passkey_challenges",
    "external_login_requests",
    "user_authenticators",
    "authorization_codes",
    "client_assertion_jtis",
    "refresh_tokens",
    "revoked_access_tokens",
    "password_reset_tokens",
    "email_verification_tokens",
];
