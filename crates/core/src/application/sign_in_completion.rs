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
use crate::application::device_enrollment::{Admission, AdmissionAttempt, DeviceGate};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session::{AuthSession, Authentication};
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::DomainError;
use crate::domain::repositories::{
    AuthSessionRepository, ClientConsentRepository, SsoSessionRepository,
};
use crate::domain::session_key::{lifetime_for, SessionBinding};
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

/// SSO セッションを作ろうとした結論。
pub enum Establishment {
    /// 作った。
    Established(EstablishedSso),
    /// 登録した端末に限る組織で、登録していない端末だった（task #916。ADR-0079）。SSO セッションは
    /// 作っていない。web は `ticket` を Cookie に置き、端末の登録の画面へ回す。
    ///
    /// ⚠ 経路ごとの outcome はこれを「ログインできた」に写してはならない。
    DeviceEnrollmentRequired { ticket: String },
}

impl Establishment {
    /// 試験・登録の直後など、関門を通ると分かっている所で使う。
    #[cfg(test)]
    pub fn expect_established(self) -> EstablishedSso {
        match self {
            Self::Established(sso) => sso,
            Self::DeviceEnrollmentRequired { .. } => panic!("device enrollment was required"),
        }
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
    /// 登録した端末の関門（task #916）。`None` は関門なし（試験だけ。api は必ず付ける）。
    device_gate: Option<Arc<DeviceGate>>,
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
            device_gate: None,
        }
    }

    /// 登録した端末の関門を付ける（task #916。⚠ api の組み立てでは必ず呼ぶ）。
    pub fn with_device_gate(mut self, gate: Arc<DeviceGate>) -> Self {
        self.device_gate = Some(gate);
        self
    }

    /// 関門を通るかを決める（関門が無ければ通す）。
    async fn admit(
        &self,
        sign_in: &SignIn<'_>,
        binding: SessionBinding,
        ctx: &RequestContext,
        now: DateTime<Utc>,
    ) -> Result<Admission, DomainError> {
        let Some(gate) = &self.device_gate else {
            return Ok(Admission::Admitted);
        };
        gate.admit(
            AdmissionAttempt {
                tenant_id: sign_in.tenant_id,
                user_id: sign_in.user_id,
                home_tenant_id: sign_in.home_tenant_id,
                methods: &sign_in.methods,
                client_id: sign_in.client_id,
                app_approved: matches!(binding, SessionBinding::AppApproval),
            },
            ctx,
            now,
        )
        .await
    }

    /// SSO セッションを作って保存し、監査に残す（`SsoSessionCreated` と成功のイベント）。
    ///
    /// 登録した端末に限る組織で登録していない端末なら、作らずに
    /// [`Establishment::DeviceEnrollmentRequired`] を返す（task #916）。
    pub async fn establish_sso(
        &self,
        sign_in: SignIn<'_>,
        ctx: &RequestContext,
        now: DateTime<Utc>,
    ) -> Result<Establishment, DomainError> {
        self.establish_sso_with_binding(sign_in, SessionBinding::Unbound, ctx, now)
            .await
    }

    /// 結び付けの種類を決めて SSO セッションを作る（長さは `session_key::lifetime_for`）。
    ///
    /// 確立のときに結び付けが決まっているのは「アプリで承認」だけ（task #892。ADR-0077）。DBSC は確立の
    /// 後に結び付くので、ここでは `Unbound` で作り、結び付けたときに延ばす（ADR-0074）。
    pub async fn establish_sso_with_binding(
        &self,
        sign_in: SignIn<'_>,
        binding: SessionBinding,
        ctx: &RequestContext,
        now: DateTime<Utc>,
    ) -> Result<Establishment, DomainError> {
        if let Admission::EnrollmentRequired { ticket } =
            self.admit(&sign_in, binding, ctx, now).await?
        {
            return Ok(Establishment::DeviceEnrollmentRequired { ticket });
        }
        let lifetime = self
            .settings
            .sso_session_lifetime(sign_in.home_tenant_id)
            .await?;
        let (idle_expires_at, absolute_expires_at) = lifetime_for(
            now,
            now + lifetime.idle,
            binding,
            false,
            lifetime.absolute,
            lifetime.bound,
        );
        let session_id = crypto::random_hex(32);
        let session = SsoSession::establish(
            crypto::sha256_hex(&session_id),
            sign_in.user_id,
            now,
            idle_expires_at - now,
            absolute_expires_at - now,
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
        Ok(Establishment::Established(EstablishedSso {
            session,
            session_id,
        }))
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
