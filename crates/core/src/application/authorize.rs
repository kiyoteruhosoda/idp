//! 認可エンドポイントのユースケース（設計仕様 §4.2、ADR-0018 決定 2・3）。
//!
//! `/authorize` はブラウザ Cookie を読み書きしない。認可リクエストを検証して AuthSession を作成し、
//! **単回・短命のハンドル**を発行して web へのハンドオフ（`{web}/{tenant}/login?auth_session=...`）
//! に載せる（[`AuthorizeService::authorize`]）。SSO 復元・同意チェック・code 発行は、web が
//! ハンドルと自ドメインの `sso_session_id` を `/internal/authorize/resume` で渡してきた時点で行う
//! （[`AuthorizeService::resume`]）。`prompt` / `max_age` の評価も resume まで持ち越す。
//!
//! エラー方針: `client_id` / `redirect_uri` が無効な場合はリダイレクトせず、
//! それ以外のエラーは `redirect_uri` にエラーコードを付与して返す。

use crate::application::application_access::ApplicationAccessService;
use crate::application::audit::RequestContext;
use crate::application::code_issuance::{CodeIssuance, CodeIssuanceService, IssueCodeCommand};
use crate::application::consent::consent_is_granted;
use crate::application::sso_restore::SsoRestorer;
use crate::application::tenant_resolution::TenantResolutionService;
use crate::domain::auth_session::{AuthSession, AuthSessionId, Authentication, HandoffHandle};
use crate::domain::authentication_policy::{
    evaluate_policies, AuthenticationContext, PolicyDecision,
};
use crate::domain::authorization_request::{
    AuthorizationParameters, AuthorizationRequest, AuthorizationRequestRejection,
};
use crate::domain::clock::Clock;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::OAuthErrorCode;
use crate::domain::repositories::{
    AuthSessionRepository, AuthenticationPolicyRepository, ClientConsentRepository,
    ClientRepository,
};
use crate::domain::response_mode::AuthorizationResponse;
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::AuthenticationMethod;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// web ハンドオフ用ハンドルの有効期限（秒）。`/authorize` の 302 を web が受けて
/// `/internal/authorize/resume` へ渡すまでの片道だけを覆えばよいため、auth_session 本体の
/// TTL より大幅に短くする（単回・短命・固定束縛。ADR-0018 決定 3）。
const HANDLE_TTL_SECS: i64 = 60;

pub enum AuthorizeOutcome {
    /// 検証成功。AuthSession 作成済み。単回ハンドルを URL に載せて web の `/login` へ 302 する
    /// （SSO の有無は web が resume で確かめる。ADR-0018 決定 2）。
    HandoffToWeb { handle: String },
    /// `redirect_uri` にエラーを付与して 302。
    ErrorRedirect { location: String },
    /// リダイレクト不可のエラー（client_id / redirect_uri が無効）。
    FatalError {
        error: OAuthErrorCode,
        description: String,
    },
}

/// `/internal/authorize/resume` のコマンド（web がハンドルと SSO Cookie 値を転送する）。
#[derive(Debug)]
pub struct ResumeCommand {
    /// `/authorize` が URL に載せた単回ハンドル。
    pub handle: String,
    /// web の host-only `sso_session_id` Cookie の値（無ければ未ログイン）。
    pub sso_session_id: Option<String>,
}

pub enum ResumeOutcome {
    /// SSO 復元・同意済みにより code 発行済み。`query` なら `location` へ 302、`form_post` なら
    /// `location` へ hidden フィールドを POST する自動送信フォームを描く（G12）。
    Redirect {
        location: String,
        form_post: Option<Vec<(String, String)>>,
        /// 復元した SSO セッションの絶対期限までの長さ（秒）。web が Cookie を発行し直すときの
        /// `Max-Age`（ADR-0058）。
        sso_absolute_ttl_secs: u64,
    },
    /// リクエスト続行不可（`prompt=none` で未ログイン・未同意など）。エラー付き RP URL へ 302。
    ErrorRedirect { location: String },
    /// SSO 有効だが同意が必要。web は `auth_session_id` を Cookie 化して `/consent` へ。
    ConsentRequired {
        auth_session_id: String,
        /// `Redirect` と同じ（復元した SSO セッションの絶対期限までの長さ）。
        sso_absolute_ttl_secs: u64,
    },
    /// 認証が必要。web は `auth_session_id` を Cookie 化してログインフォームを表示する。
    LoginRequired { auth_session_id: String },
    /// SSO は復元できたが、このアプリの利用が許可されていない（ADR-0054）。⚠ **RP へ戻さない。**
    /// SSO Cookie は既に手元にあるので、ここでは画面を出すだけでよい。
    ApplicationNotPermitted {
        /// 画面に出すアプリ名。
        application_name: String,
    },
    /// ハンドルが無効・期限切れ・使用済み（`/authorize` からやり直し）。
    ExpiredHandle,
    /// 内部エラー（RP へのリダイレクトも組み立てられない段階での失敗）。
    Internal(String),
}

/// ログイン画面の文脈取得（`/internal/authorize/login-context`。G12）の結果。
pub enum LoginContextOutcome {
    /// 進行中の認可要求が持ち込んだ表示ヒント（いずれも未指定なら `None`）。
    Ok {
        login_hint: Option<String>,
        ui_locales: Option<String>,
        /// この認可要求の `redirect_uri`。web がログイン画面の CSP `form-action` に許可する
        /// オリジンの出所（SSO と同意が揃っていれば、ログインフォームの送信はそのまま RP へ
        /// リダイレクトするため）。
        redirect_uri: String,
        /// 認可要求を出したクライアントの表示名（`Clients.app_name`）。ログイン画面が
        /// 「どのアプリへログインするのか」を示すために使う。表示名が引けないときは `None`
        /// （`client_id` は**出さない**。利用者に意味が無く、画面を汚すだけのため）。
        client_name: Option<String>,
        /// フローのテナントの表示名（`Tenants.name`）。同じ IdP が複数の組織を受け持つため、
        /// 「どの組織のアカウントで入るのか」を示すために使う。引けないときは `None`。
        tenant_name: Option<String>,
    },
    /// `auth_session_id` が無効・期限切れ（web は文脈なしで描画を続ける）。
    SessionExpired,
    /// 内部エラー。
    Internal(String),
}

/// 復元した SSO セッションに対するポリシー判定の結論。
enum RestoredPolicy {
    /// 復元してよい。
    Ok,
    /// 復元は認めないが、ログインし直せば通りうる（`max_age` 超過と同じ扱い）。
    Reauthenticate,
    /// 拒否。ログインし直しても通らないのでフローを終える。
    Denied,
    Internal(String),
}

pub struct AuthorizeService {
    clients: Arc<dyn ClientRepository>,
    auth_sessions: Arc<dyn AuthSessionRepository>,
    /// SSO 復元の共通判定（SAML SSO と共有。[`crate::application::sso_restore`]）。
    sso_restorer: Arc<SsoRestorer>,
    client_consents: Arc<dyn ClientConsentRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    clock: Arc<dyn Clock>,
    auth_session_ttl: Duration,
    /// 認証ポリシー（AP2/AP3）。**SSO 復元でも評価する**ために持つ。復元は「以前の認証を
    /// 使い回す」操作なので、認可要求ごとに変わる条件（`acr_values`・`client_ids`）や、
    /// 復元後に変わったポリシーが効かなくなる。
    authentication_policies: Arc<dyn AuthenticationPolicyRepository>,
    /// 認証ポリシーの宛先（`conditions.application_ids`）を解決する（ADR-0054）。
    /// フローが持っているのは `client_id` だけなので、アプリへの読み替えをここで挟む。
    applications: Arc<ApplicationAccessService>,
    /// 一致するポリシーが無い場合の既定動作（AP2）。テナントの値を参照のたびに引く（ADR-0058 §4）。
    settings: Arc<dyn EffectiveTenantSettings>,
    /// ログイン画面へ出すテナント表示名の引き当て先（`login_context` でのみ使う）。
    /// リポジトリを直に持たず解決サービスを通すのは、同じ行を同じリクエストの入口
    /// （`TenantResolver`）が既に引いており、その TTL キャッシュに相乗りするためである。
    tenants: Arc<TenantResolutionService>,
}

impl AuthorizeService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        sso_restorer: Arc<SsoRestorer>,
        client_consents: Arc<dyn ClientConsentRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        clock: Arc<dyn Clock>,
        auth_session_ttl: std::time::Duration,
        authentication_policies: Arc<dyn AuthenticationPolicyRepository>,
        applications: Arc<ApplicationAccessService>,
        settings: Arc<dyn EffectiveTenantSettings>,
        tenants: Arc<TenantResolutionService>,
    ) -> Self {
        Self {
            clients,
            auth_sessions,
            sso_restorer,
            client_consents,
            code_issuance,
            clock,
            auth_session_ttl: Duration::from_std(auth_session_ttl)
                .expect("auth session TTL out of range"),
            authentication_policies,
            applications,
            settings,
            tenants,
        }
    }

    pub async fn authorize(
        &self,
        tenant: TenantContext,
        params: AuthorizationParameters,
    ) -> AuthorizeOutcome {
        // 1. client の解決（無効ならリダイレクトしない）。client はフローのテナントに属するもの
        // だけを解決する（テナント分離。ADR-0009 §8）。
        let Some(client_id) = non_empty(params.client_id.as_deref()) else {
            return fatal(OAuthErrorCode::InvalidRequest, "client_id is required");
        };
        let client = match self
            .clients
            .find_by_client_id(tenant.tenant_id(), client_id)
            .await
        {
            Ok(Some(c)) => c,
            Ok(None) => return fatal(OAuthErrorCode::InvalidClient, "unknown client_id"),
            Err(e) => {
                tracing::error!(error = %e, "failed to load client");
                return fatal(OAuthErrorCode::ServerError, "internal error");
            }
        };

        // 2. 認可要求を受理する（検証はドメインが持つ）。
        let request = match AuthorizationRequest::accept(&params, &client) {
            Ok(request) => request,
            Err(AuthorizationRequestRejection::NotRedirectable { error, description }) => {
                return fatal(error, description);
            }
            Err(AuthorizationRequestRejection::Redirectable {
                redirect_uri,
                state,
                error,
                description,
            }) => {
                return AuthorizeOutcome::ErrorRedirect {
                    location: error_redirect_with_state(
                        &redirect_uri,
                        error,
                        description,
                        state.as_deref(),
                    ),
                };
            }
        };

        // 3. AuthSession を作成し、単回ハンドルを発行して web へハンドオフする（ADR-0018 決定 2）。
        //    SSO Cookie は api からは見えないため、SSO 復元・`prompt`/`max_age` の評価は resume で行う。
        let (session, handle) = AuthSession::start(
            tenant.tenant_id(),
            request,
            self.clock.now(),
            self.auth_session_ttl,
            Duration::seconds(HANDLE_TTL_SECS),
        );
        if let Err(e) = self.auth_sessions.create(&session).await {
            tracing::error!(error = %e, "failed to create auth session");
            return AuthorizeOutcome::ErrorRedirect {
                location: redirect_with_error(
                    session.request(),
                    OAuthErrorCode::ServerError,
                    "failed to start authorization",
                ),
            };
        }

        AuthorizeOutcome::HandoffToWeb {
            handle: handle.into_string(),
        }
    }

    /// web ハンドオフの再開（`/internal/authorize/resume`。ADR-0018 決定 2）。
    ///
    /// ハンドルを単回消費して AuthSession を特定し、web から渡された `sso_session_id` で
    /// SSO 復元 → `max_age` → 同意チェック → code 発行（従来 `/authorize` が Cookie で行っていた
    /// 判定）を行う。`prompt=none` の失敗は RP へのエラーリダイレクトとして返す。
    pub async fn resume(
        &self,
        tenant: TenantContext,
        cmd: ResumeCommand,
        ctx: &RequestContext,
    ) -> ResumeOutcome {
        let now = self.clock.now();

        // 1. ハンドルから AuthSession を特定し、単回使用として消費する。
        let (mut session, auth_session_id) =
            match self.exchange_handoff(tenant, &cmd.handle, now).await {
                Ok(exchanged) => exchanged,
                Err(outcome) => return outcome,
            };

        // 2. SSO 復元で完了できるならそこで終える。
        if let Some(outcome) = self
            .complete_with_sso(
                tenant,
                &mut session,
                cmd.sso_session_id.as_deref(),
                ctx,
                now,
            )
            .await
        {
            return outcome;
        }

        // 3. SSO で完了できない: prompt=none はログイン画面を出せないのでエラー（フロー終了）。
        if session.request().forbids_interaction() {
            let _ = self.auth_sessions.delete(session.id_hash()).await;
            return ResumeOutcome::ErrorRedirect {
                location: redirect_with_error(
                    session.request(),
                    OAuthErrorCode::LoginRequired,
                    "login required",
                ),
            };
        }

        ResumeOutcome::LoginRequired {
            auth_session_id: auth_session_id.into_string(),
        }
    }

    /// ハンドルを `auth_session_id` と交換する（単回。並行する交換は片方だけが勝つ）。
    async fn exchange_handoff(
        &self,
        tenant: TenantContext,
        handle: &str,
        now: DateTime<Utc>,
    ) -> Result<(AuthSession, AuthSessionId), ResumeOutcome> {
        let Some(handle) = HandoffHandle::from_presented(handle) else {
            return Err(ResumeOutcome::ExpiredHandle);
        };
        let mut session = match self
            .auth_sessions
            .find_by_handoff(tenant.tenant_id(), &handle.hash())
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => return Err(ResumeOutcome::ExpiredHandle),
            Err(e) => return Err(ResumeOutcome::Internal(e.to_string())),
        };
        let Ok(exchange) = session.exchange_handoff(now) else {
            return Err(ResumeOutcome::ExpiredHandle);
        };
        match self.auth_sessions.save_handoff_exchange(&exchange).await {
            Ok(true) => Ok((session, exchange.into_issued())),
            // 並行する交換に負けた・再利用 → 単回使用として拒否する。
            Ok(false) => Err(ResumeOutcome::ExpiredHandle),
            Err(e) => Err(ResumeOutcome::Internal(e.to_string())),
        }
    }

    /// SSO セッションを復元して認可を完了させる。完了できない（＝ログインへ進む）なら `None`。
    ///
    /// `prompt=login` / `prompt=select_account` は常に再認証。SSO 確認の失敗は致命ではなく、
    /// ログインへフォールバックする。
    async fn complete_with_sso(
        &self,
        tenant: TenantContext,
        session: &mut AuthSession,
        sso_session_id: Option<&str>,
        ctx: &RequestContext,
        now: DateTime<Utc>,
    ) -> Option<ResumeOutcome> {
        if session.request().forces_reauthentication() {
            return None;
        }
        let sso_session_id = non_empty(sso_session_id)?;
        let restored = match self
            .sso_restorer
            .try_resume(tenant, sso_session_id, ctx)
            .await
        {
            Ok(restored) => restored?,
            Err(e) => {
                tracing::error!(error = %e, "failed to check SSO session");
                return None;
            }
        };

        // 認証ポリシー（AP2/AP3）を**この認可要求の文脈で**評価する。復元対象のセッションが確立
        // されたときとは、クライアントも `acr_values` も違いうる。評価しないと、RP が `acr_values`
        // で WebAuthn 必須ポリシーを起動しても、パスワードだけで確立された既存 SSO が黙って再利用
        // される。満たさない場合は `max_age` 超過と同じ扱い（＝再認証へ落とす）にする。拒否ポリシー
        // だけは再認証しても通らないので、その場でフローを終える。
        let policy = self
            .evaluate_for_restored_session(
                tenant,
                session.request(),
                restored.user_id,
                &restored.authentication_methods,
                ctx,
                now,
            )
            .await;
        match policy {
            RestoredPolicy::Ok => {}
            RestoredPolicy::Reauthenticate => return None,
            RestoredPolicy::Denied => {
                let _ = self.auth_sessions.delete(session.id_hash()).await;
                return Some(ResumeOutcome::ErrorRedirect {
                    location: redirect_with_error(
                        session.request(),
                        OAuthErrorCode::AccessDenied,
                        "denied by authentication policy",
                    ),
                });
            }
            RestoredPolicy::Internal(e) => return Some(ResumeOutcome::Internal(e)),
        }
        // `max_age` 超過 → ログインへ（SSO は復元しない）。
        if session
            .request()
            .authentication_is_too_old(restored.auth_time, now)
        {
            return None;
        }

        // ID Token へ載せる `sid`（G5）は復元したセッションから導出する。
        let authentication = Authentication::new(
            restored.user_id,
            restored.auth_time,
            Some(crate::domain::sso_session::sid_of(&restored.session_hash)),
            Some(restored.authentication_methods),
        );
        Some(
            self.authorize_restored(
                tenant,
                session,
                authentication,
                restored.absolute_ttl_secs,
                ctx,
            )
            .await,
        )
    }

    /// 復元した SSO の認証で、同意を確かめて code を発行する（未同意なら同意画面へ）。
    async fn authorize_restored(
        &self,
        tenant: TenantContext,
        session: &mut AuthSession,
        authentication: Authentication,
        sso_absolute_ttl_secs: u64,
        ctx: &RequestContext,
    ) -> ResumeOutcome {
        // 同意チェック（`prompt=consent` の場合は既存同意を無視）。
        let request = session.request();
        if !request.forces_consent()
            && self
                .check_consent(tenant, authentication.user_id(), request)
                .await
        {
            return self
                .issue_restored_code(tenant, session, authentication, sso_absolute_ttl_secs, ctx)
                .await;
        }

        // 未同意（または `prompt=consent`）。`prompt=none` では同意画面を出せないのでエラー。
        if request.forbids_interaction() {
            let _ = self.auth_sessions.delete(session.id_hash()).await;
            return ResumeOutcome::ErrorRedirect {
                location: redirect_with_error(
                    request,
                    OAuthErrorCode::ConsentRequired,
                    "consent required",
                ),
            };
        }

        // 同意画面へ: AuthSession を認証済み状態にして web に返す。SSO からの復元でも id を
        // 再生成する（SEC7）。同意画面へ渡す `auth_session_id` は再生成後の値。
        let completion = session.complete_authentication(authentication);
        if let Err(e) = self.auth_sessions.save_authentication(&completion).await {
            tracing::error!(error = %e, "failed to mark session for consent");
            return ResumeOutcome::ErrorRedirect {
                location: redirect_with_error(
                    session.request(),
                    OAuthErrorCode::ServerError,
                    "failed to start consent",
                ),
            };
        }
        ResumeOutcome::ConsentRequired {
            auth_session_id: completion.into_issued().into_string(),
            sso_absolute_ttl_secs,
        }
    }

    /// 同意済みの SSO 復元で code を発行し、AuthSession を削除する。
    async fn issue_restored_code(
        &self,
        tenant: TenantContext,
        session: &AuthSession,
        authentication: Authentication,
        sso_absolute_ttl_secs: u64,
        ctx: &RequestContext,
    ) -> ResumeOutcome {
        let cmd = IssueCodeCommand {
            tenant,
            request: session.request().clone(),
            authentication,
        };
        match self.code_issuance.issue(cmd, ctx).await {
            // 復元した SSO は通っているが、このアプリの利用が許可されていない（ADR-0054）。
            // RP へは戻さない。
            Ok(CodeIssuance::ApplicationDenied { application_name }) => {
                ResumeOutcome::ApplicationNotPermitted { application_name }
            }
            Ok(CodeIssuance::Issued(code)) => {
                if let Err(e) = self.auth_sessions.delete(session.id_hash()).await {
                    tracing::warn!(
                        error = %e,
                        "failed to delete auth session after SSO code issuance"
                    );
                }
                let dispatch =
                    AuthorizationDispatch::from(session.request().success_response(&code));
                ResumeOutcome::Redirect {
                    location: dispatch.location,
                    form_post: dispatch.form_post,
                    sso_absolute_ttl_secs,
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to issue authorization code");
                ResumeOutcome::ErrorRedirect {
                    location: redirect_with_error(
                        session.request(),
                        OAuthErrorCode::ServerError,
                        "failed to issue authorization code",
                    ),
                }
            }
        }
    }

    /// 復元した SSO セッションを、この認可要求の文脈で認証ポリシーに掛ける（AP2/AP3）。
    ///
    /// 判定材料は「復元セッションが記録している認証方式」（AP4）。`require_mfa` は多要素で
    /// 確立されたセッションなら満たし、`require_specific_method` は記録された方式が要求に
    /// 一致するかで見る。User Verification は記録に無いため、WebAuthn を含むセッションのみ
    /// UV 済みとみなす（パスキー登録・認証は UV 必須で行っている）。
    async fn evaluate_for_restored_session(
        &self,
        tenant: TenantContext,
        request: &AuthorizationRequest,
        user_id: Uuid,
        methods: &[AuthenticationMethod],
        ctx: &RequestContext,
        now: DateTime<Utc>,
    ) -> RestoredPolicy {
        let default_effect = match self
            .settings
            .policy_default_effect(tenant.tenant_id())
            .await
        {
            Ok(effect) => effect,
            Err(e) => return RestoredPolicy::Internal(e.to_string()),
        };
        let policies = match self
            .authentication_policies
            .list_enabled_for_tenant(tenant.tenant_id())
            .await
        {
            Ok(p) => p,
            Err(e) => return RestoredPolicy::Internal(e.to_string()),
        };
        // 認証ポリシーの宛先はアプリ（ADR-0054 の決定 5）。
        let application_id = match self
            .applications
            .policy_target_for_oidc_client(tenant.tenant_id(), request.client_id())
            .await
        {
            Ok(id) => id,
            Err(e) => return RestoredPolicy::Internal(e.to_string()),
        };
        let decision = evaluate_policies(
            &policies,
            &AuthenticationContext {
                application_id,
                user_id,
                ip_address: ctx.ip_address.as_deref(),
                now,
                requested_acr: &request.requested_acr(),
            },
            default_effect,
        );
        let user_verified = methods.contains(&AuthenticationMethod::WebAuthn);
        match &decision {
            PolicyDecision::Deny { .. } => RestoredPolicy::Denied,
            PolicyDecision::RequireMfa { .. } if methods.iter().any(|m| m.is_second_factor()) => {
                RestoredPolicy::Ok
            }
            PolicyDecision::RequireMfa { .. } => RestoredPolicy::Reauthenticate,
            PolicyDecision::RequireMethods { .. }
                if decision
                    .unmet_method_requirement(methods, user_verified)
                    .is_none() =>
            {
                RestoredPolicy::Ok
            }
            PolicyDecision::RequireMethods { .. } => RestoredPolicy::Reauthenticate,
            PolicyDecision::Allow { .. } => RestoredPolicy::Ok,
        }
    }

    /// 同意チェック: ユーザーがクライアントに対してすべての scope に同意済みか確認する。
    ///
    /// 確認に失敗したら「未同意」として扱う（同意画面へ進むだけで、誤って code を出すことはない）。
    async fn check_consent(
        &self,
        tenant: TenantContext,
        user_id: Uuid,
        request: &AuthorizationRequest,
    ) -> bool {
        match consent_is_granted(
            self.client_consents.as_ref(),
            tenant.tenant_id(),
            user_id,
            request,
        )
        .await
        {
            Ok(granted) => granted,
            Err(e) => {
                tracing::error!(error = %e, "failed to check consent");
                false
            }
        }
    }

    /// ログイン画面の文脈（`/internal/authorize/login-context`。G12）。
    ///
    /// 認可要求が持ち込んだ `login_hint` / `ui_locales` を、進行中の `auth_session_id` から引き直す。
    /// web は resume の 303 でこれらを手元に残せないため、画面描画のたびに取り直す口が要る。
    ///
    /// あわせて、ログイン画面が「どこへログインするのか」を示すための表示名
    /// （クライアントの `app_name`・テナントの `name`）も返す。これは画面が持ち得ない情報で、
    /// 無いと利用者はどのアプリのどの組織へ入るのか分からないまま資格情報を入力することになる。
    ///
    /// 返すのは**表示のためのヒントだけ**で、利用者・同意状態には触れない（`auth_session_id` は
    /// 提示できれば認可セッションを操作できる bearer credential だが、この経路は読み出しのみ）。
    pub async fn login_context(
        &self,
        tenant: TenantContext,
        auth_session_id: &str,
    ) -> LoginContextOutcome {
        let Some(auth_session_id) = AuthSessionId::from_presented(auth_session_id) else {
            return LoginContextOutcome::SessionExpired;
        };
        let session = match self
            .auth_sessions
            .find(tenant.tenant_id(), &auth_session_id.hash())
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => return LoginContextOutcome::SessionExpired,
            Err(e) => return LoginContextOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(self.clock.now()) {
            return LoginContextOutcome::SessionExpired;
        }
        let request = session.request();
        // 表示名は「あれば出す」だけの飾りで、引けなくてもログインは続けられなければならない。
        // 取得に失敗しても文脈全体を落とさず、その欄だけ空にする。
        let client_name = match self
            .clients
            .find_by_client_id(tenant.tenant_id(), request.client_id())
            .await
        {
            Ok(client) => client.map(|c| c.app_name),
            Err(e) => {
                tracing::warn!(error = %e, "could not read the client name for the login page");
                None
            }
        };
        let tenant_name = match self.tenants.resolve(tenant.tenant_id()).await {
            Ok(t) => t.map(|t| t.name),
            Err(e) => {
                tracing::warn!(error = %e, "could not read the tenant name for the login page");
                None
            }
        };
        LoginContextOutcome::Ok {
            login_hint: request.login_hint().map(str::to_string),
            ui_locales: request.ui_locales().map(str::to_string),
            redirect_uri: request.redirect_uri().to_string(),
            client_name,
            tenant_name,
        }
    }
}

fn non_empty(v: Option<&str>) -> Option<&str> {
    v.filter(|s| !s.is_empty())
}

fn fatal(error: OAuthErrorCode, description: &str) -> AuthorizeOutcome {
    AuthorizeOutcome::FatalError {
        error,
        description: description.to_string(),
    }
}

/// 認可要求の `redirect_uri` へエラーを付けて戻す URL（`state` を透過返却）。
///
/// ⚠ `/authorize` と resume の失敗は `response_mode` を見ずに**クエリで**返す（従来どおり）。
/// 認可セッションの完了点（ログイン・同意など）のエラーは
/// [`AuthorizationRequest::error_response`] で `response_mode` に従う。
fn redirect_with_error(
    request: &AuthorizationRequest,
    error: OAuthErrorCode,
    description: &str,
) -> String {
    error_redirect_with_state(
        request.redirect_uri(),
        error,
        description,
        Some(request.state()),
    )
}

/// `redirect_uri` にクエリパラメータを足した URL を組み立てる。
///
/// `redirect_uri` は登録済み値との完全一致を通っているが、**ここでパニックさせない**（SEC12）。
/// 登録時の検証をすり抜けた値（DB の直接編集・過去の緩い検証で入った行）が 1 つあるだけで、
/// その RP を使う認可要求が毎回リクエストごと落ちることになる。解析できない場合は素朴に
/// クエリを連結して返し、壊れているのは当該 RP の設定だけに留める。
fn append_query(redirect_uri: &str, pairs: &[(&str, &str)]) -> String {
    if let Ok(mut url) = url::Url::parse(redirect_uri) {
        {
            let mut query = url.query_pairs_mut();
            for (key, value) in pairs {
                query.append_pair(key, value);
            }
        }
        return url.to_string();
    }
    tracing::error!("redirect_uri is not a parsable URL; falling back to query concatenation");
    let encoded: Vec<String> = pairs
        .iter()
        .map(|(key, value)| {
            let value =
                percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC);
            format!("{key}={value}")
        })
        .collect();
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    format!("{redirect_uri}{separator}{}", encoded.join("&"))
}

/// 認可応答を各ユースケースの outcome へ載せる形（G12）。
///
/// `location` は **`query` なら 302 先の完成 URL、`form_post` ならフォームの送信先**
/// （＝パラメータの付かない `redirect_uri`）である。`form_post` が `Some` のとき、
/// 呼び出し側は `location` へ hidden フィールドを POST する自動送信フォームを描く。
///
/// 2 つの形を 1 つの型にまとめず「URL ＋任意のフィールド」にしてあるのは、既存の経路
/// （`query`）を触らずに済ませるため。`form_post` を見落とした経路は `location` で 302 し、
/// RP は「コードの無い戻り」を受け取ってエラーになる——認可コードが URL に載って履歴・
/// `Referer` に残るよりは、目に見えて失敗する方がよい。
#[derive(Debug, Clone, Default)]
pub struct AuthorizationDispatch {
    pub location: String,
    /// `form_post` のとき、POST する hidden フィールド（`code` / `state`、またはエラー）。
    pub form_post: Option<Vec<(String, String)>>,
}

impl From<AuthorizationResponse> for AuthorizationDispatch {
    fn from(response: AuthorizationResponse) -> Self {
        Self {
            location: response.location(),
            form_post: response.is_form_post().then(|| response.parameters.clone()),
        }
    }
}

/// `redirect_uri?code=...&state=...` を構築する（state は透過返却、設計仕様 §2.2）。
///
/// `response_mode` を見ないため、認可セッションが手元にある経路では
/// [`AuthorizationRequest::success_response`] を使う。
pub fn code_redirect(redirect_uri: &str, code: &str, state: &str) -> String {
    append_query(redirect_uri, &[("code", code), ("state", state)])
}

/// `redirect_uri?error=...&error_description=...&state=...` を構築する（state は省略可）。
pub fn error_redirect_with_state(
    redirect_uri: &str,
    error: OAuthErrorCode,
    description: &str,
    state: Option<&str>,
) -> String {
    let mut pairs: Vec<(&str, &str)> = vec![
        ("error", error.as_str()),
        ("error_description", description),
    ];
    if let Some(state) = state {
        pairs.push(("state", state));
    }
    append_query(redirect_uri, &pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_redirect_urls_with_encoded_query() {
        let location = code_redirect("https://client.example.com/cb?keep=1", "c o+de", "st&ate");
        assert!(location.starts_with("https://client.example.com/cb?keep=1&"));
        assert!(location.contains("code=c+o%2Bde"));
        assert!(location.contains("state=st%26ate"));

        let location = error_redirect_with_state(
            "https://client.example.com/cb",
            OAuthErrorCode::InvalidScope,
            "scope must include `openid`",
            Some("xyz"),
        );
        assert!(location.contains("error=invalid_scope"));
        assert!(location.contains("state=xyz"));
    }
}
