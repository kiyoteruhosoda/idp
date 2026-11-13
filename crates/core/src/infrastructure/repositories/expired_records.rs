//! Concentrates expired-row cleanup (G2) in one file.
//!
//! Tables of in-progress state and one-time tokens grow without bound if left alone. Previously only the `log` table was
//! deleted periodically, and nobody deleted the others (`passkey_challenges` implemented `delete_expired`
//! but had no caller). `revoked_access_tokens` is used for the `/introspect` blacklist check,
//! so its bloat turns directly into latency.
//!
//! Growing a background loop per table would leave cleanup gaps with each addition, so
//! a single port, [`ExpiringRecordStore`], declares "can be cleaned up", and
//! [`crate::application::expired_record_purge::ExpiredRecordPurgeService`] runs them in one task.
//!
//! **This file is the list of GC targets.** When adding a table with an expiry, add an implementation here and
//! put it in `all_expiring_record_stores` and `PURGED_TABLES` (omissions are caught by the integration test
//! `expired_record_purge::every_table_with_an_expiry_column_is_swept`).

use crate::domain::error::Result;
use crate::domain::repositories::{
    AuthSessionRepository, ExpiringRecordStore, ExternalLoginRequestRepository,
    PasskeyChallengeRepository, SamlSsoRequestRepository, SsoSessionRepository,
    UserAuthenticatorRepository,
};
use crate::infrastructure::db::Db;
use crate::infrastructure::repositories::{
    app_approver::{SqlxApprovalRequestRepository, SqlxApproverEnrollmentRepository},
    auth_session::SqlxAuthSessionRepository,
    authorization_code::SqlxAuthorizationCodeRepository,
    client_assertion::SqlxClientAssertionReplayRepository,
    dpop_proof::SqlxDpopProofReplayRepository,
    email_verification_token::SqlxEmailVerificationTokenRepository,
    external_idp::SqlxExternalLoginRequestRepository,
    passkey_challenge::SqlxPasskeyChallengeRepository,
    password_reset_token::SqlxPasswordResetTokenRepository,
    refresh_token::SqlxRefreshTokenRepository,
    revoked_access_token::SqlxRevokedAccessTokenRepository,
    saml_sso_request::SqlxSamlSsoRequestRepository,
    sso_session::SqlxSsoSessionRepository,
    user_authenticator::SqlxUserAuthenticatorRepository,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;

/// Common implementation deleting rows with `expires_at <= now` (every GC target table has this shape).
async fn delete_by_expires_at(pool: &Db, table: &str, now: DateTime<Utc>) -> Result<u64> {
    // Only constants in this module are passed as table names (no external input is assembled).
    let sql = format!("DELETE FROM {table} WHERE expires_at <= ?");
    let result = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(now.naive_utc())
        .execute(pool)
        .await
        .map_err(|e| crate::domain::error::DomainError::Repository(e.to_string()))?;
    Ok(result.rows_affected())
}

/// Macro declaring cleanup targets in the form "delegate to the owning repository's trait".
/// Repositories that already have `delete_expired` call it; tables without one are DELETEd directly.
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

/// Tables used only for cleanup (use cases never touch their expired rows) are deleted directly here
/// without widening a repository trait.
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
purge_directly!(SqlxApproverEnrollmentRepository, "app_approver_enrollments");
purge_directly!(SqlxApprovalRequestRepository, "app_approval_requests");
purge_directly!(SqlxClientAssertionReplayRepository, "client_assertion_jtis");
purge_directly!(SqlxDpopProofReplayRepository, "dpop_proof_jtis");
purge_directly!(SqlxRefreshTokenRepository, "refresh_tokens");
purge_directly!(SqlxRevokedAccessTokenRepository, "revoked_access_tokens");
purge_directly!(SqlxPasswordResetTokenRepository, "password_reset_tokens");
purge_directly!(
    SqlxEmailVerificationTokenRepository,
    "email_verification_tokens"
);

/// Builds the cleanup handles for every table with an expiry (**the list of GC targets**).
///
/// The set built here at startup is passed to [`crate::application::expired_record_purge::ExpiredRecordPurgeService`].
/// Failing to follow when a table is added is caught by the integration test
/// `expired_record_purge::every_table_with_an_expiry_column_is_swept`.
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
        Arc::new(SqlxDpopProofReplayRepository::new(pool.clone())),
        Arc::new(SqlxRefreshTokenRepository::new(pool.clone())),
        Arc::new(SqlxRevokedAccessTokenRepository::new(pool.clone())),
        Arc::new(SqlxPasswordResetTokenRepository::new(pool.clone())),
        Arc::new(SqlxEmailVerificationTokenRepository::new(pool.clone())),
        Arc::new(SqlxApproverEnrollmentRepository::new(pool.clone())),
        Arc::new(SqlxApprovalRequestRepository::new(pool)),
    ]
}

/// Names of the tables the GC must cover (maintained as a pair with `all_expiring_record_stores`).
/// An integration test compares against `information_schema` and detects tables with `expires_at` that are not listed.
pub const PURGED_TABLES: &[&str] = &[
    "auth_sessions",
    "saml_sso_requests",
    "sso_sessions",
    "passkey_challenges",
    "external_login_requests",
    "user_authenticators",
    "authorization_codes",
    "client_assertion_jtis",
    "dpop_proof_jtis",
    "refresh_tokens",
    "revoked_access_tokens",
    "password_reset_tokens",
    "email_verification_tokens",
    "app_approver_enrollments",
    "app_approval_requests",
];
