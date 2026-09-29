//! 認証が成立した後の共通の後段（SSO の確立 → 認可フローの続き）。
//!
//! ログイン・MFA・パスキー・パスワード変更・外部 IdP の 5 経路は、それぞれの方法で利用者を確かめた
//! あと、同じ手順で終わる:
//!
//! 1. [`SignInCompletion::establish_sso`] —— SSO セッションを作って保存し、監査に残す
//! 2. [`SignInCompletion::continue_authorization`] —— 認可フローの途中から来ていれば、その
//!    AuthSession に認証を記録し（id を付け替える。SEC7）、同意を確かめ、code を発行して
//!    AuthSession を消す
//!
//! # SSO セッションを先に保存する
//!
//! 認証の記録（`sid` を AuthSession へ預ける）より先に SSO セッションを保存する。逆にすると、
//! SSO の保存に失敗したときに「認証済みで、存在しない SSO セッションの `sid` を持つ AuthSession」が
//! 残り、同意の承諾がそれで code を出せてしまう。この順なら、失敗して残るのは Cookie を誰にも
//! 渡していない SSO の行だけである（期限で消える）。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authorize::AuthorizationDispatch;
use crate::application::code_issuance::{CodeIssuance, CodeIssuanceService, IssueCodeCommand};
use crate::application::consent::consent_is_granted;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session::{AuthSession, Authentication};
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::DomainError;
use crate::domain::repositories::{
    AuthSessionRepository, ClientConsentRepository, SsoSessionRepository,
};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::AuthenticationMethod;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// 成立した認証（誰が・どの方式で・どこで）。
pub struct SignIn<'a> {
    /// 認証したテナント（フローのテナント。監査の宛先）。
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    /// 利用者の所属元テナント。SSO セッションの寿命はこちらの値（SSO セッションは全テナントで
    /// 共有されるため。ADR-0058）。
    pub home_tenant_id: TenantId,
    /// 実際に検証された方式（ADR-0043。ID Token の `acr` / `amr` の出所）。
    pub methods: Vec<AuthenticationMethod>,
    /// 監査に載せるクライアント（認可フローの外なら `None`）。
    pub client_id: Option<&'a str>,
    /// 成功として監査に残すイベントと、その詳細。
    pub success_event: AuditEventType,
    pub success_detail: Option<String>,
}

/// 確立した SSO セッション（web へ渡す Cookie の平文を含む）。
pub struct EstablishedSso {
    session: SsoSession,
    session_id: String,
}

impl EstablishedSso {
    /// web が host-only Cookie に置く値（平文）。
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Cookie の `Max-Age`（絶対期限までの秒数。ADR-0058）。
    pub fn absolute_ttl_secs(&self) -> u64 {
        self.session.absolute_ttl_secs()
    }

    pub fn session(&self) -> &SsoSession {
        &self.session
    }
}

/// 認可フローの続きの結論。
pub enum AuthorizationContinuation {
    /// 同意が要る。web は新しい `auth_session_id` で同意画面へ進む。
    ConsentRequired { auth_session_id: String },
    /// このアプリの利用が許可されていない（ADR-0054）。⚠ **RP へ戻さない。**
    ApplicationNotPermitted { application_name: String },
    /// code を発行した。RP へ戻す。
    Authorized(AuthorizationDispatch),
}

pub struct SignInCompletion {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    auth_sessions: Arc<dyn AuthSessionRepository>,
    client_consents: Arc<dyn ClientConsentRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    audit: Arc<AuditService>,
    settings: Arc<dyn EffectiveTenantSettings>,
}

impl SignInCompletion {
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        client_consents: Arc<dyn ClientConsentRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        audit: Arc<AuditService>,
        settings: Arc<dyn EffectiveTenantSettings>,
    ) -> Self {
        Self {
            sso_sessions,
            auth_sessions,
            client_consents,
            code_issuance,
            audit,
            settings,
        }
    }

    /// SSO セッションを作って保存し、監査に残す（`SsoSessionCreated` と成功のイベント）。
    pub async fn establish_sso(
        &self,
        sign_in: SignIn<'_>,
        ctx: &RequestContext,
        now: DateTime<Utc>,
    ) -> Result<EstablishedSso, DomainError> {
        let lifetime = self
            .settings
            .sso_session_lifetime(sign_in.home_tenant_id)
            .await?;
        let session_id = crypto::random_hex(32);
        let session = SsoSession::establish(
            crypto::sha256_hex(&session_id),
            sign_in.user_id,
            now,
            lifetime.idle,
            lifetime.absolute,
            sign_in.methods,
            ctx.user_agent.clone(),
            ctx.ip_address.clone(),
        );
        self.sso_sessions.create(&session).await?;
        self.audit
            .record(
                AuditEventType::SsoSessionCreated,
                AuditResult::Success,
                Some(sign_in.tenant_id),
                Some(sign_in.user_id),
                sign_in.client_id,
                None,
                ctx,
            )
            .await;
        self.audit
            .record(
                sign_in.success_event,
                AuditResult::Success,
                Some(sign_in.tenant_id),
                Some(sign_in.user_id),
                sign_in.client_id,
                sign_in.success_detail.as_deref(),
                ctx,
            )
            .await;
        Ok(EstablishedSso {
            session,
            session_id,
        })
    }

    /// 認可フローを続ける: 認証を記録し（id を付け替える）、同意を確かめ、code を発行する。
    ///
    /// 認証時刻は `now`、`sid` と方式は確立した SSO セッションのもの。
    pub async fn continue_authorization(
        &self,
        tenant: TenantContext,
        session: &mut AuthSession,
        sso: &EstablishedSso,
        now: DateTime<Utc>,
        ctx: &RequestContext,
    ) -> Result<AuthorizationContinuation, DomainError> {
        let authentication = Authentication::new(
            sso.session.user_id,
            now,
            Some(sso.session.sid()),
            Some(sso.session.authentication_methods.clone()),
        );
        let completion = session.complete_authentication(authentication.clone());
        self.auth_sessions.save_authentication(&completion).await?;

        let consented = consent_is_granted(
            self.client_consents.as_ref(),
            tenant.tenant_id(),
            authentication.user_id(),
            session.request(),
        )
        .await?;
        if !consented {
            // 同意未完: AuthSession は認証済みのまま残す。
            return Ok(AuthorizationContinuation::ConsentRequired {
                auth_session_id: completion.into_issued().into_string(),
            });
        }

        let issuance = self
            .code_issuance
            .issue(
                IssueCodeCommand {
                    tenant,
                    request: session.request().clone(),
                    authentication,
                },
                ctx,
            )
            .await?;
        let code = match issuance {
            CodeIssuance::Issued(code) => code,
            // 認証は通っているが、このアプリの利用が許可されていない（ADR-0054）。RP へは戻さない。
            CodeIssuance::ApplicationDenied { application_name } => {
                return Ok(AuthorizationContinuation::ApplicationNotPermitted { application_name });
            }
        };

        // code を出したので AuthSession は役目を終えた（Cookie の失効は web が行う）。
        if let Err(e) = self.auth_sessions.delete(session.id_hash()).await {
            tracing::warn!(error = %e, "failed to delete auth session after code issuance");
        }
        Ok(AuthorizationContinuation::Authorized(
            session.request().success_response(&code).into(),
        ))
    }
}
