//! authorization code 発行の共通モジュール（設計仕様 §4.2 / §4.3 で共用）。
//!
//! code は 256bit の暗号学的乱数として生成し、DB には `SHA-256(code)` のみ保存する。
//! 発行時に `authorization_code.issued` を監査ログへ記録する。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::authorization_code::AuthorizationCode;
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::repositories::AuthorizationCodeRepository;
use crate::domain::values::CodeChallengeMethod;
use crate::infrastructure::crypto;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// code 発行に必要な認可情報（AuthSession または SSO 復元から引き継ぐ）。
pub struct IssueCodeCommand {
    pub user_id: Uuid,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub nonce: String,
    pub auth_time: DateTime<Utc>,
    pub code_challenge: String,
    pub code_challenge_method: CodeChallengeMethod,
}

pub struct CodeIssuanceService {
    codes: Arc<dyn AuthorizationCodeRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ttl: Duration,
}

impl CodeIssuanceService {
    pub fn new(
        codes: Arc<dyn AuthorizationCodeRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ttl: std::time::Duration,
    ) -> Self {
        Self {
            codes,
            audit,
            clock,
            ttl: Duration::from_std(ttl).expect("authorization code TTL out of range"),
        }
    }

    /// authorization code を発行して平文 code を返す（呼び出し側が redirect_uri に付与する）。
    pub async fn issue(
        &self,
        cmd: IssueCodeCommand,
        ctx: &RequestContext,
    ) -> Result<String, DomainError> {
        let code = crypto::random_token(32);
        let now = self.clock.now();

        let record = AuthorizationCode {
            code_hash: crypto::sha256_hex(&code),
            user_id: cmd.user_id,
            client_id: cmd.client_id.clone(),
            redirect_uri: cmd.redirect_uri,
            scope: cmd.scope,
            nonce: cmd.nonce,
            auth_time: cmd.auth_time,
            code_challenge: cmd.code_challenge,
            code_challenge_method: cmd.code_challenge_method,
            expires_at: now + self.ttl,
            used_at: None,
            created_at: now,
            updated_at: now,
        };

        self.codes.create(&record).await?;

        self.audit
            .record(
                AuditEventType::AuthorizationCodeIssued,
                AuditResult::Success,
                Some(cmd.user_id),
                Some(&cmd.client_id),
                None,
                ctx,
            )
            .await;

        Ok(code)
    }
}
