//! 外部 IdP ログインのユースケース（AP10。ユーザー認証・認証ポリシー仕様書 §13）。
//!
//! 2 段構え:
//!
//! 1. [`start`](ExternalLoginService::start) — 外部 IdP の認可エンドポイントへ送る URL を組み立て、
//!    `state` / `nonce` / PKCE の `code_verifier` を進行状態として保存する。
//! 2. [`callback`](ExternalLoginService::callback) — 戻ってきた `state` で進行状態を**単回消費**し、
//!    認可コードを ID Token へ交換、検証済みクレームの `iss` + `sub` で利用者を解決して
//!    SSO セッションを発行する。
//!
//! # 利用者の解決（§13.2）
//!
//! `iss` + `sub` の連携が既にあればその利用者。無ければ:
//!
//! - プロバイダが `allow_auto_link` を有効にしていて、外部 IdP が**検証済みと主張する**メールが
//!   テナント内の既存利用者と一致すれば、その利用者へ連携を作る。
//! - それ以外は拒否する（`NotLinked`）。**利用者を勝手に作らない** — 外部 IdP で認証できる人を
//!   そのままテナントの利用者にすると、招待・権限付与という管理の入口が意味を失うため。
//!
//! # 認証ポリシー
//!
//! 外部 IdP で本人確認できても、テナントの認証ポリシー（AP2/AP4）は同じように適用する。
//! 「外部で認証した」ことは `deny` を免れる理由にならない。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authorize::code_dispatch;
use crate::application::code_issuance::{CodeIssuanceService, IssueCodeCommand};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session;
use crate::domain::authentication_policy::{
    evaluate_policies, AuthenticationContext, DefaultPolicyEffect, PolicyDecision,
};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::external_idp::{ExternalIdentity, ExternalLoginRequest};
use crate::domain::external_oidc_port::{ExternalOidcClient, ExternalTokenRequest};
use crate::domain::id_generator::IdGenerator;
use crate::domain::pkce;
use crate::domain::repositories::{
    AuthSessionRepository, AuthenticationPolicyRepository, ClientConsentRepository,
    ExternalIdentityProviderRepository, ExternalIdentityRepository, ExternalLoginRequestRepository,
    SsoSessionRepository, UserRepository,
};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::AuthenticationMethod;
use chrono::{DateTime, Duration, Utc};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use std::sync::Arc;

/// 進行状態の寿命。外部 IdP でのログイン操作（同意・MFA を含む）に十分な長さ。
const REQUEST_TTL_SECS: i64 = 600;
/// `state` / `nonce` の乱数バイト数（いずれも 256bit）。
const STATE_BYTES: usize = 32;

/// 外部 IdP ログインの開始結果。
pub enum StartOutcome {
    /// 外部 IdP の認可エンドポイントへ 302 する。
    Redirect {
        location: String,
    },
    /// プロバイダが無い・無効。
    ProviderUnavailable,
    Internal(String),
}

pub struct CallbackCommand {
    /// 外部 IdP から戻ってきた `state`。
    pub state: String,
    /// 認可コード。
    pub code: String,
}

/// 外部 IdP ログインの完了結果。
pub enum CallbackOutcome {
    /// 認証成功。SSO Cookie を発行する。
    ///
    /// `location` は認証後に送る先。OIDC 認可フローの途中から来ていれば **code 付きの
    /// `redirect_uri`**（＝ RP へ戻す）、そうでなければ本サービス内の戻り先。ここを web 側に
    /// 組み立てさせない（認可要求のパラメータは auth_session にしか無い）。
    Success {
        location: SuccessLocation,
        sso_session_id: String,
        user_language: Option<String>,
    },
    /// 外部 IdP での認証は通ったが、RP への同意がまだ。同意画面へ誘導する
    /// （他のログイン経路と同じ扱い。外部で認証したことは同意の代わりにならない）。
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        user_language: Option<String>,
    },
    /// `state` が無効・期限切れ・二重使用（外部 IdP からやり直し）。
    StateExpired,
    /// 外部 IdP での認証は通ったが、この IdP に対応する利用者が居ない（連携も自動連携も不成立）。
    NotLinked,
    /// 対応する利用者は居るが無効・ロック中。
    UserUnavailable,
    /// 認証ポリシーによる拒否。
    PolicyDenied,
    /// 外部 IdP との通信・トークン検証に失敗した。
    ExternalFailure,
    Internal(String),
}

/// 認証成功後の戻り先。
pub enum SuccessLocation {
    /// OIDC 認可フローの続き。`location` は `query` なら code 付きの `redirect_uri`、
    /// `form_post` ならフォームの送信先（G12。`form_post` が `Some` のとき自動送信フォームを描く）。
    Redirect {
        location: String,
        form_post: Option<Vec<(String, String)>>,
    },
    /// 認可フローの外から来た。web が自分の画面（アカウント設定）へ戻す。
    Account,
}

pub struct ExternalLoginService {
    providers: Arc<dyn ExternalIdentityProviderRepository>,
    identities: Arc<dyn ExternalIdentityRepository>,
    requests: Arc<dyn ExternalLoginRequestRepository>,
    users: Arc<dyn UserRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    /// OIDC 認可フローの途中から来た場合に続きを進めるための依存（他のログイン経路と共通）。
    auth_sessions: Arc<dyn AuthSessionRepository>,
    client_consents: Arc<dyn ClientConsentRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    authentication_policies: Arc<dyn AuthenticationPolicyRepository>,
    oidc: Arc<dyn ExternalOidcClient>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    key_encryption_key: [u8; 32],
    /// コールバックを受ける web の公開ベース URL（`{base}/{tenant}/external/{code}/callback`）。
    public_web_base_url: String,
    sso_idle_ttl: Duration,
    sso_absolute_ttl: Duration,
    policy_default_effect: DefaultPolicyEffect,
}

impl ExternalLoginService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        providers: Arc<dyn ExternalIdentityProviderRepository>,
        identities: Arc<dyn ExternalIdentityRepository>,
        requests: Arc<dyn ExternalLoginRequestRepository>,
        users: Arc<dyn UserRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        client_consents: Arc<dyn ClientConsentRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        authentication_policies: Arc<dyn AuthenticationPolicyRepository>,
        oidc: Arc<dyn ExternalOidcClient>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
        key_encryption_key: [u8; 32],
        public_web_base_url: String,
        sso_idle_ttl: std::time::Duration,
        sso_absolute_ttl: std::time::Duration,
        policy_default_effect: DefaultPolicyEffect,
    ) -> Self {
        Self {
            providers,
            identities,
            requests,
            users,
            sso_sessions,
            auth_sessions,
            client_consents,
            code_issuance,
            authentication_policies,
            oidc,
            audit,
            clock,
            ids,
            key_encryption_key,
            public_web_base_url,
            sso_idle_ttl: Duration::from_std(sso_idle_ttl).expect("SSO idle TTL out of range"),
            sso_absolute_ttl: Duration::from_std(sso_absolute_ttl)
                .expect("SSO absolute TTL out of range"),
            policy_default_effect,
        }
    }

    /// 外部 IdP への認可要求を組み立てる。
    pub async fn start(
        &self,
        tenant: TenantContext,
        provider_code: &str,
        auth_session_id: Option<String>,
    ) -> StartOutcome {
        let provider = match self
            .providers
            .find_by_code(tenant.tenant_id(), provider_code)
            .await
        {
            Ok(Some(p)) if p.enabled => p,
            Ok(_) => return StartOutcome::ProviderUnavailable,
            Err(e) => return StartOutcome::Internal(e.to_string()),
        };

        let now = self.clock.now();
        let state = crypto::random_token(STATE_BYTES);
        let nonce = crypto::random_token(STATE_BYTES);
        // PKCE は外部 IdP が public クライアント登録でも安全に交換できるようにするため常に付ける
        //（S256 のみ。本 IdP 自身が `/authorize` で強制しているのと同じ方針）。
        let code_verifier = crypto::random_token(STATE_BYTES);
        let code_challenge = pkce::s256_challenge(&code_verifier);

        let code_verifier_encrypted =
            match crypto::encrypt(code_verifier.as_bytes(), &self.key_encryption_key) {
                Ok(v) => v,
                Err(e) => return StartOutcome::Internal(e.to_string()),
            };

        let request = ExternalLoginRequest {
            id: self.ids.new_id(),
            tenant_id: tenant.tenant_id(),
            provider_id: provider.id,
            state_hash: crypto::sha256_hex(&state),
            nonce: nonce.clone(),
            code_verifier_encrypted,
            auth_session_id_hash: auth_session_id.as_deref().map(auth_session::id_hash),
            expires_at: now + Duration::seconds(REQUEST_TTL_SECS),
            created_at: now,
        };
        if let Err(e) = self.requests.create(&request).await {
            return StartOutcome::Internal(e.to_string());
        }

        let redirect_uri = self.redirect_uri(tenant, &provider.provider_code);
        let encode = |v: &str| utf8_percent_encode(v, NON_ALPHANUMERIC).to_string();
        let separator = if provider.authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        let location = format!(
            "{}{separator}response_type=code&client_id={}&redirect_uri={}&scope={}\
             &state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
            provider.authorization_endpoint,
            encode(&provider.client_id),
            encode(&redirect_uri),
            encode(&provider.effective_scopes().join(" ")),
            encode(&state),
            encode(&nonce),
            encode(&code_challenge),
        );
        StartOutcome::Redirect { location }
    }

    /// 外部 IdP からのコールバックを処理する。
    pub async fn callback(
        &self,
        tenant: TenantContext,
        cmd: CallbackCommand,
        ctx: &RequestContext,
    ) -> CallbackOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. `state` で進行状態を引き、**削除できた側だけ**が続行する（単回使用）。
        let state_hash = crypto::sha256_hex(&cmd.state);
        let request = match self.requests.find_by_state(tenant_id, &state_hash).await {
            Ok(Some(r)) => r,
            Ok(None) => return CallbackOutcome::StateExpired,
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        };
        match self.requests.consume(request.id).await {
            Ok(true) => {}
            Ok(false) => return CallbackOutcome::StateExpired,
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        }
        if request.is_expired_at(now) {
            return CallbackOutcome::StateExpired;
        }

        // 2. プロバイダ設定を読み直す（進行中に無効化された可能性がある）。
        let provider = match self
            .providers
            .find_by_id(tenant_id, request.provider_id)
            .await
        {
            Ok(Some(p)) if p.enabled => p,
            Ok(_) => return CallbackOutcome::StateExpired,
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        };

        // 3. 秘密を復号する。
        let code_verifier =
            match crypto::decrypt(&request.code_verifier_encrypted, &self.key_encryption_key) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(v) => v,
                    Err(e) => return CallbackOutcome::Internal(e.to_string()),
                },
                Err(e) => return CallbackOutcome::Internal(e.to_string()),
            };
        let client_secret = match provider.client_secret_encrypted.as_deref() {
            Some(encrypted) => match crypto::decrypt(encrypted, &self.key_encryption_key) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(v) => Some(v),
                    Err(e) => return CallbackOutcome::Internal(e.to_string()),
                },
                Err(e) => return CallbackOutcome::Internal(e.to_string()),
            },
            None => None,
        };

        // 4. コードを交換し、ID Token を検証する（検証はポートの実装に閉じている）。
        let redirect_uri = self.redirect_uri(tenant, &provider.provider_code);
        let claims = match self
            .oidc
            .exchange_code(ExternalTokenRequest {
                token_endpoint: &provider.token_endpoint,
                jwks_uri: &provider.jwks_uri,
                expected_issuer: &provider.issuer,
                client_id: &provider.client_id,
                client_secret: client_secret.as_deref(),
                redirect_uri: &redirect_uri,
                code: &cmd.code,
                code_verifier: &code_verifier,
                expected_nonce: &request.nonce,
            })
            .await
        {
            Ok(c) => c,
            Err(e) => {
                // 外部 IdP 側の事情（証明書・鍵・設定ミス）も含むため、利用者へは詳細を返さず
                // 運用ログにだけ残す。
                tracing::warn!(
                    error = %e,
                    provider = %provider.provider_code,
                    "external idp token exchange or verification failed"
                );
                self.record_failure(tenant, &provider.provider_code, "token_verification", ctx)
                    .await;
                return CallbackOutcome::ExternalFailure;
            }
        };

        // 5. `iss` + `sub` で利用者を解決する。
        let identity = match self
            .identities
            .find_by_subject(provider.id, &claims.issuer, &claims.subject)
            .await
        {
            Ok(v) => v,
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        };
        let user_id = match identity.as_ref() {
            Some(existing) => existing.user_id,
            None => match self.auto_link(tenant, &provider, &claims).await {
                Ok(Some(id)) => id,
                Ok(None) => {
                    self.record_failure(tenant, &provider.provider_code, "not_linked", ctx)
                        .await;
                    return CallbackOutcome::NotLinked;
                }
                Err(e) => return CallbackOutcome::Internal(e),
            },
        };

        // 6. 利用者の状態を確認する。
        let user = match self.users.find_by_id(user_id).await {
            Ok(Some(u)) if u.is_active() && !u.is_locked_at(now) => u,
            Ok(_) => {
                self.record_failure(tenant, &provider.provider_code, "user_unavailable", ctx)
                    .await;
                return CallbackOutcome::UserUnavailable;
            }
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        };

        // 7. 認証ポリシー（AP2/AP3）。外部で認証したことは `deny` を免れる理由にならない。
        //
        //    OIDC 認可フローの途中から来た場合は、その auth_session を**評価より先に**引いて
        //    クライアントと `acr_values` を文脈に載せる。空文脈で評価すると `client_ids` や
        //    `requested_acr` を条件に持つポリシーが一致せず、外部 IdP 経由なら条件付きの拒否・
        //    方式指定を回避できてしまう（後段でこの auth_session を使って code を発行するので、
        //    「クライアント文脈を持たない」わけではない）。ポータル起点なら空のままでよい。
        let originating_session = match request.auth_session_id_hash.as_deref() {
            Some(id_hash) => match self.auth_sessions.find_by_id_hash(tenant_id, id_hash).await {
                Ok(session) => session,
                Err(e) => return CallbackOutcome::Internal(e.to_string()),
            },
            None => None,
        };
        let requested_acr = originating_session
            .as_ref()
            .map(|s| s.requested_acr())
            .unwrap_or_default();
        let decision = match self
            .authentication_policies
            .list_enabled_for_tenant(tenant_id)
            .await
        {
            Ok(policies) => evaluate_policies(
                &policies,
                &AuthenticationContext {
                    client_id: originating_session.as_ref().map(|s| s.client_id.as_str()),
                    user_id: user.id,
                    ip_address: ctx.ip_address.as_deref(),
                    now,
                    requested_acr: &requested_acr,
                },
                self.policy_default_effect,
            ),
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        };
        match &decision {
            PolicyDecision::Allow { .. } => {}
            PolicyDecision::Deny { policy_code } => {
                self.record_policy_denied(tenant, user.id, &format!("policy={policy_code}"), ctx)
                    .await;
                return CallbackOutcome::PolicyDenied;
            }
            PolicyDecision::RequireMfa { policy_code } => {
                // 外部 IdP での認証は本 IdP から見ると単一要素（外部側の MFA は観測できない。
                // §13.3）。MFA 必須のポリシーが掛かる利用者は、この経路では通さない。
                self.record_policy_denied(
                    tenant,
                    user.id,
                    &format!("policy={policy_code} reason=external_idp_is_single_factor"),
                    ctx,
                )
                .await;
                return CallbackOutcome::PolicyDenied;
            }
            PolicyDecision::RequireMethods { .. } => {
                // 外部 IdP 経由で記録される方式は `external_idp` のみ。要求と食い違えば通さない
                // （外部側でどの認証器が使われたかは観測できないため、要求を満たしたとみなせない）。
                if let Some(unmet) =
                    decision.unmet_method_requirement(&[AuthenticationMethod::ExternalIdp], false)
                {
                    self.record_policy_denied(
                        tenant,
                        user.id,
                        &format!(
                            "policy={} reason=method_required required={}",
                            unmet.policy_code,
                            unmet.requirement.describe()
                        ),
                        ctx,
                    )
                    .await;
                    return CallbackOutcome::PolicyDenied;
                }
            }
        }

        // 8. 連携の利用時刻を更新する（初回連携は `auto_link` が作成済み）。
        if let Some(existing) = identity {
            if let Err(e) = self.identities.touch_last_used(existing.id, now).await {
                tracing::warn!(error = %e, "failed to record external identity usage");
            }
        }

        // 9. SSO セッションを発行する。
        let sso_session_id = crypto::random_hex(32);
        let sso = SsoSession::establish(
            crypto::sha256_hex(&sso_session_id),
            user.id,
            now,
            self.sso_idle_ttl,
            self.sso_absolute_ttl,
            vec![AuthenticationMethod::ExternalIdp],
            ctx.user_agent.clone(),
            ctx.ip_address.clone(),
        );
        if let Err(e) = self.sso_sessions.create(&sso).await {
            return CallbackOutcome::Internal(e.to_string());
        }

        self.audit
            .record(
                AuditEventType::SsoSessionCreated,
                AuditResult::Success,
                Some(tenant_id),
                Some(user.id),
                None,
                None,
                ctx,
            )
            .await;
        self.audit
            .record(
                AuditEventType::ExternalLoginSucceeded,
                AuditResult::Success,
                Some(tenant_id),
                Some(user.id),
                None,
                Some(&format!("provider={}", provider.provider_code)),
                ctx,
            )
            .await;

        // 10. OIDC 認可フローの途中から来ていれば、その続きを進める（同意確認 → code 発行）。
        //     ここで進めないと、認可要求のパラメータ（client_id・redirect_uri・PKCE・nonce）は
        //     auth_session にしか無いため RP へ戻れない。
        let Some(auth_session_id_hash) = request.auth_session_id_hash.clone() else {
            return CallbackOutcome::Success {
                location: SuccessLocation::Account,
                sso_session_id,
                user_language: user.language.clone(),
            };
        };
        self.resume_authorization(
            tenant,
            &auth_session_id_hash,
            &user,
            &sso,
            sso_session_id,
            now,
            ctx,
        )
        .await
    }

    /// 外部 IdP で認証した利用者について、中断していた OIDC 認可フローを再開する。
    ///
    /// 手順は他のログイン経路（`LoginService` / `MfaLoginService`）の後半と同じ: 認証済みとして
    /// auth_session に紐づけ、同意を確認し、authorization code を発行して RP へ戻す。共通部分は
    /// `CodeIssuanceService` に寄せてあるため、ここで写しているのは「同意が要るかの判定」だけ。
    ///
    /// auth_session が既に期限切れなら、外部 IdP での認証自体は成立しているので SSO は発行した
    /// まま、アカウント画面へ戻す（RP へは戻れないが、ログインし直しは要らない）。
    #[allow(clippy::too_many_arguments)]
    async fn resume_authorization(
        &self,
        tenant: TenantContext,
        auth_session_id_hash: &str,
        user: &crate::domain::user::User,
        sso: &SsoSession,
        sso_session_id: String,
        now: DateTime<Utc>,
        ctx: &RequestContext,
    ) -> CallbackOutcome {
        let tenant_id = tenant.tenant_id();
        let session = match self
            .auth_sessions
            .find_by_id_hash(tenant_id, auth_session_id_hash)
            .await
        {
            Ok(Some(session)) if !session.is_expired_at(now) => session,
            Ok(_) => {
                // 認可の再開はできないが、ログイン自体は成立している。
                tracing::info!("external login finished after its auth session had expired");
                return CallbackOutcome::Success {
                    location: SuccessLocation::Account,
                    sso_session_id,
                    user_language: user.language.clone(),
                };
            }
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        };

        // 認証時刻と `sid` を auth_session へ記録する（ID Token の `auth_time` / `sid` の出所）。
        // id も再生成する（SEC7）。
        let rotated_id = crypto::random_hex(32);
        let rotated_id_hash = auth_session::id_hash(&rotated_id);
        if let Err(e) = self
            .auth_sessions
            .set_authenticated_user(
                &session.id_hash,
                &rotated_id_hash,
                user.id,
                now,
                Some(&sso.sid()),
            )
            .await
        {
            return CallbackOutcome::Internal(e.to_string());
        }

        // 同意チェック（`openid` は暗黙同意）。
        let scopes_needing_consent: Vec<String> = session
            .scope
            .iter()
            .filter(|s| s.as_str() != "openid")
            .cloned()
            .collect();
        let consented = if scopes_needing_consent.is_empty() {
            true
        } else {
            match self
                .client_consents
                .find(tenant_id, user.id, &session.client_id)
                .await
            {
                Ok(Some(consent)) => consent.covers(&scopes_needing_consent),
                Ok(None) => false,
                Err(e) => return CallbackOutcome::Internal(e.to_string()),
            }
        };
        if !consented {
            return CallbackOutcome::ConsentRequired {
                auth_session_id: rotated_id,
                sso_session_id,
                user_language: user.language.clone(),
            };
        }

        let code = match self
            .code_issuance
            .issue(
                IssueCodeCommand {
                    tenant,
                    user_id: user.id,
                    client_id: session.client_id.clone(),
                    redirect_uri: session.redirect_uri.clone(),
                    scope: session.scope.clone(),
                    nonce: session.nonce.clone(),
                    auth_time: now,
                    sid: Some(sso.sid()),
                    code_challenge: session.code_challenge.clone(),
                    code_challenge_method: session.code_challenge_method,
                },
                ctx,
            )
            .await
        {
            Ok(c) => c,
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        };

        if let Err(e) = self.auth_sessions.delete(&rotated_id_hash).await {
            tracing::warn!(error = %e, "failed to delete auth session after external login");
        }

        let dispatch = code_dispatch(&session, &code);
        CallbackOutcome::Success {
            location: SuccessLocation::Redirect {
                location: dispatch.location,
                form_post: dispatch.form_post,
            },
            sso_session_id,
            user_language: user.language.clone(),
        }
    }

    /// 検証済みメールの一致で既存利用者へ連携する（プロバイダが許可している場合のみ）。
    ///
    /// 一致した利用者が居ても、外部 IdP が `email_verified` を主張していなければ連携しない。
    /// 主張の無いメールで結び付けると、外部 IdP に登録できる誰でも他人のアカウントへ入れる。
    async fn auto_link(
        &self,
        tenant: TenantContext,
        provider: &crate::domain::external_idp::ExternalIdentityProvider,
        claims: &crate::domain::external_idp::ExternalClaims,
    ) -> Result<Option<uuid::Uuid>, String> {
        if !provider.allow_auto_link || !claims.email_verified {
            return Ok(None);
        }
        let Some(email) = claims
            .email
            .as_deref()
            .map(str::trim)
            .filter(|e| !e.is_empty())
        else {
            return Ok(None);
        };
        let user = self
            .users
            .find_by_email(tenant.tenant_id(), email)
            .await
            .map_err(|e| e.to_string())?;
        let Some(user) = user.filter(|u| u.is_active()) else {
            return Ok(None);
        };

        let now = self.clock.now();
        let identity = ExternalIdentity {
            id: self.ids.new_id(),
            user_id: user.id,
            provider_id: provider.id,
            external_issuer: claims.issuer.clone(),
            external_subject: claims.subject.clone(),
            created_at: now,
            last_used_at: Some(now),
        };
        match self.identities.create(&identity).await {
            Ok(()) => Ok(Some(user.id)),
            // 並行して同じ連携が作られた場合は、勝った側の連携を使う（作り直さない）。
            Err(crate::domain::error::DomainError::Conflict(_)) => {
                let existing = self
                    .identities
                    .find_by_subject(provider.id, &claims.issuer, &claims.subject)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(existing.map(|i| i.user_id))
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// コールバック URL（外部 IdP へ登録する `redirect_uri` と完全一致すること）。
    fn redirect_uri(&self, tenant: TenantContext, provider_code: &str) -> String {
        format!(
            "{}/{}/external/{provider_code}/callback",
            self.public_web_base_url,
            tenant.tenant_id()
        )
    }

    async fn record_failure(
        &self,
        tenant: TenantContext,
        provider_code: &str,
        reason: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::ExternalLoginFailed,
                AuditResult::Failure,
                Some(tenant.tenant_id()),
                None,
                None,
                Some(&format!("provider={provider_code} reason={reason}")),
                ctx,
            )
            .await;
    }

    async fn record_policy_denied(
        &self,
        tenant: TenantContext,
        user_id: uuid::Uuid,
        reason: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::LoginPolicyDenied,
                AuditResult::Failure,
                Some(tenant.tenant_id()),
                Some(user_id),
                None,
                Some(reason),
                ctx,
            )
            .await;
    }
}
