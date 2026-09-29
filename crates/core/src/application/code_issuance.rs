//! authorization code 発行の共通モジュール（設計仕様 §4.2 / §4.3 で共用）。
//!
//! code は 256bit の暗号学的乱数として生成し、DB には `SHA-256(code)` のみ保存する。
//! 発行時に `authorization_code.issued` を監査ログへ記録する。
//!
//! # ここが「アプリを使ってよいか」の門でもある（ADR-0054）
//!
//! ログイン・MFA・パスキー・外部 IdP・パスワード変更・同意・SSO 復元の 7 経路は、どれも最後に
//! ここへ来る
//! ——**code を発行できる経路はここだけ**である。だから判定もここに置く。認証ごとの経路へ判定を
//! 書き写すと、経路が 1 つ増えるたびに書き忘れがそのまま門を開ける。

use crate::application::application_access::{ApplicationAccessService, ApplicationGate};
use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session::Authentication;
use crate::domain::authorization_code::AuthorizationCode;
use crate::domain::authorization_request::AuthorizationRequest;
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::DomainError;
use crate::domain::repositories::AuthorizationCodeRepository;
use crate::domain::tenant_context::TenantContext;
use chrono::Duration;
use std::sync::Arc;

/// code 発行に必要な認可情報: **どの認可要求に**、**どの認証で**応えるか。
///
/// どちらも AuthSession（またはSSO 復元）から引き継ぐ。認可要求は `/authorize` で受理された
/// ときのまま、認証は ID Token の `sub` / `auth_time` / `sid` / `acr` / `amr` の出所になる。
pub struct IssueCodeCommand {
    /// code を発行するテナント（フローのテナント）。
    pub tenant: TenantContext,
    pub request: AuthorizationRequest,
    pub authentication: Authentication,
}

/// code 発行の結果。
///
/// 「拒否」を `Err` にしないのは、**呼び出し側の扱いが違う**ためである。`Err` は RP へ
/// `server_error` で戻す種類の失敗だが、割り当ての拒否は assay の画面で伝える（ADR-0054 の決定 2）。
/// 同じ型に混ぜると、どちらかの経路で取り違えたときに利用者へ出るものが変わってしまう。
pub enum CodeIssuance {
    /// 発行できた（平文の code。呼び出し側が `redirect_uri` に付与する）。
    Issued(String),
    /// このアプリの利用が許可されていない。⚠ **RP へ戻さない。**
    ApplicationDenied {
        /// 画面に出すアプリ名。「どのアプリで断られたのか」が分からないと、利用者は次に何を
        /// すればよいか（誰に頼めばよいか）を決められない。
        application_name: String,
    },
}

pub struct CodeIssuanceService {
    codes: Arc<dyn AuthorizationCodeRepository>,
    applications: Arc<ApplicationAccessService>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ttl: Duration,
}

impl CodeIssuanceService {
    pub fn new(
        codes: Arc<dyn AuthorizationCodeRepository>,
        applications: Arc<ApplicationAccessService>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ttl: std::time::Duration,
    ) -> Self {
        Self {
            codes,
            applications,
            audit,
            clock,
            ttl: Duration::from_std(ttl).expect("authorization code TTL out of range"),
        }
    }

    /// authorization code を発行する。
    ///
    /// 判定（ADR-0054）は**書き込みより先**に行う。後に置くと、断ったときに使われない code が
    /// DB に残る。
    pub async fn issue(
        &self,
        cmd: IssueCodeCommand,
        ctx: &RequestContext,
    ) -> Result<CodeIssuance, DomainError> {
        if let ApplicationGate::Denied {
            application_name, ..
        } = self
            .applications
            .check(
                cmd.tenant.tenant_id(),
                cmd.request.client_id(),
                cmd.authentication.user_id(),
                ctx,
            )
            .await
        {
            return Ok(CodeIssuance::ApplicationDenied { application_name });
        }

        let code = crypto::random_token(32);
        let now = self.clock.now();

        let IssueCodeCommand {
            tenant,
            request,
            authentication,
        } = &cmd;
        let record = AuthorizationCode {
            code_hash: crypto::sha256_hex(&code),
            tenant_id: tenant.tenant_id(),
            user_id: authentication.user_id(),
            client_id: request.client_id().to_string(),
            redirect_uri: request.redirect_uri().to_string(),
            scope: request.scope().to_vec(),
            nonce: request.nonce().to_string(),
            auth_time: authentication.auth_time(),
            sid: authentication.sso_sid().map(str::to_string),
            authentication_methods: authentication.methods().map(<[_]>::to_vec),
            code_challenge: request.pkce().challenge().to_string(),
            code_challenge_method: request.pkce().method(),
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
                Some(tenant.tenant_id()),
                Some(authentication.user_id()),
                Some(request.client_id()),
                None,
                ctx,
            )
            .await;

        Ok(CodeIssuance::Issued(code))
    }
}
