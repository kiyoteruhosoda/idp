//! SAML SP-initiated SSO のユースケース（`/{tenant_id}/saml/sso`）。
//!
//! OIDC の認可フロー（ADR-0018 決定 2）と同じハンドオフ方式を採る。api はブラウザ Cookie を
//! 読まないため、[`SamlSsoService::begin`] は AuthnRequest を検証して [`SamlSsoRequest`] を作成し、
//! **単回・短命のハンドル**を web へのリダイレクト URL（`{web}/{tenant}/saml/continue?handle=...`）
//! に載せる。web は自ドメインの host-only `sso_session_id` Cookie とともに
//! `/internal/saml/resume`（[`SamlSsoService::resume`]）を呼び、SSO が有効なら署名付き
//! SAML Response を受け取って ACS へ自動 POST するフォームを描画する。SSO 未確立なら
//! `saml_request_id` を Cookie 化してポータルログインへ誘導し、ログイン成功後に同じ resume を
//! `saml_request_id` で再開する。
//!
//! エラー方針: 検証済みの ACS（登録済み SP）が確定する前のエラーは信頼できる返送先が無いため、
//! RP へリダイレクトせず 400 として呼び出し元へ返す（プロトコルエラーは翻訳しない。CLAUDE.md）。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::key_service::KeyService;
use crate::application::sso_restore::SsoRestorer;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::issuer::tenant_issuer;
use crate::domain::repositories::{
    SamlServiceProviderRepository, SamlSsoRequestRepository, UserRepository,
};
use crate::domain::saml_authn_request::{
    decode_post_binding, decode_redirect_binding, parse_authn_request,
};
use crate::domain::saml_response::{
    build_signed_response_xml, generate_saml_id, SamlResponseInput, SamlSigner,
};
use crate::domain::saml_service_provider::SamlServiceProvider;
use crate::domain::saml_sso_request::SamlSsoRequest;
use crate::domain::tenant_context::TenantContext;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Duration;
use std::sync::Arc;

/// web ハンドオフ用ハンドルの有効期限（秒）。`/saml/sso` の 302 を web が受けて
/// `/internal/saml/resume` へ渡すまでの片道だけを覆えばよい（OIDC の authorize と同値）。
const HANDLE_TTL_SECS: i64 = 60;

/// 発行するアサーションの有効期限（`NotOnOrAfter` / `SubjectConfirmationData`）。
/// ブラウザ経由の即時 POST を想定した短命値（設計仕様 §2.2 の authorization code と同じ思想）。
const ASSERTION_TTL_SECS: i64 = 300;

/// DB 列幅に合わせた入力上限（`saml_sso_requests.request_id` / `relay_state`）。
const MAX_REQUEST_ID_LEN: usize = 1024;
const MAX_RELAY_STATE_LEN: usize = 1024;

/// `SAMLRequest` の受信バインディング。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamlSsoBinding {
    /// HTTP-Redirect（GET クエリ。base64 + raw DEFLATE）。
    Redirect,
    /// HTTP-POST（フォーム。base64）。
    Post,
}

/// `/saml/sso` の受信内容。
pub struct SamlBeginCommand {
    pub binding: SamlSsoBinding,
    pub saml_request: String,
    pub relay_state: Option<String>,
}

pub enum SamlBeginOutcome {
    /// 検証成功。単回ハンドルを URL に載せて web の `/saml/continue` へ 302 する。
    HandoffToWeb { handle: String },
    /// AuthnRequest が不正（未登録 SP・ACS 不一致・解析失敗）。検証済みの返送先が無いため
    /// リダイレクトせず 400 を返す（`reason` は RP 開発者向けの固定英語文言）。
    BadRequest { reason: String },
    /// 内部エラー。
    Internal(String),
}

/// `/internal/saml/resume` のコマンド。初回は `handle`（単回交換）、ログイン後の再開は
/// `saml_request_id`（web の host-only Cookie）で行う。
pub struct SamlResumeCommand {
    pub handle: Option<String>,
    pub saml_request_id: Option<String>,
    /// web の host-only `sso_session_id` Cookie の値（無ければ未ログイン）。
    pub sso_session_id: Option<String>,
}

pub enum SamlResumeOutcome {
    /// SSO 有効。署名付き SAML Response（base64）を ACS へ自動 POST するフォームを web が描画する。
    Completed {
        acs_url: String,
        /// `SAMLResponse` フォーム値（base64 済み）。
        saml_response: String,
        relay_state: Option<String>,
    },
    /// 認証が必要。web は `saml_request_id` を host-only Cookie 化してポータルログインへ誘導する。
    LoginRequired { saml_request_id: String },
    /// ハンドル・リクエストが無効・期限切れ・使用済み（SP からやり直し）。
    Expired,
    /// 内部エラー。
    Internal(String),
}

pub struct SamlSsoService {
    service_providers: Arc<dyn SamlServiceProviderRepository>,
    requests: Arc<dyn SamlSsoRequestRepository>,
    users: Arc<dyn UserRepository>,
    sso_restorer: Arc<SsoRestorer>,
    keys: Arc<KeyService>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    /// 基底 issuer（`config.issuer()`）。テナント issuer = IdP entityID の合成に使う。
    base_issuer: String,
    request_ttl: Duration,
}

impl SamlSsoService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        service_providers: Arc<dyn SamlServiceProviderRepository>,
        requests: Arc<dyn SamlSsoRequestRepository>,
        users: Arc<dyn UserRepository>,
        sso_restorer: Arc<SsoRestorer>,
        keys: Arc<KeyService>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        base_issuer: String,
        request_ttl: std::time::Duration,
    ) -> Self {
        Self {
            service_providers,
            requests,
            users,
            sso_restorer,
            keys,
            audit,
            clock,
            base_issuer,
            request_ttl: Duration::from_std(request_ttl).expect("SAML request TTL out of range"),
        }
    }

    /// AuthnRequest を検証し、[`SamlSsoRequest`] を作成して web ハンドオフ用ハンドルを発行する。
    pub async fn begin(
        &self,
        tenant: TenantContext,
        cmd: SamlBeginCommand,
        ctx: &RequestContext,
    ) -> SamlBeginOutcome {
        // 1. デコード・解析。
        let decoded = match cmd.binding {
            SamlSsoBinding::Redirect => decode_redirect_binding(&cmd.saml_request),
            SamlSsoBinding::Post => decode_post_binding(&cmd.saml_request),
        };
        let xml = match decoded {
            Ok(xml) => xml,
            Err(e) => return self.reject(tenant, None, &e.to_string(), ctx).await,
        };
        let parsed = match parse_authn_request(&xml) {
            Ok(parsed) => parsed,
            Err(e) => return self.reject(tenant, None, &e.to_string(), ctx).await,
        };

        // 2. 登録済み SP の解決（テナント境界内。ADR-0009 §8）。
        let provider = match self
            .service_providers
            .find_by_entity_id(tenant.tenant_id(), &parsed.issuer)
            .await
        {
            Ok(Some(p)) => p,
            Ok(None) => {
                return self
                    .reject(
                        tenant,
                        Some(&parsed.issuer),
                        "unknown SAML service provider",
                        ctx,
                    )
                    .await
            }
            Err(e) => return SamlBeginOutcome::Internal(e.to_string()),
        };
        if !provider.enabled {
            return self
                .reject(
                    tenant,
                    Some(&parsed.issuer),
                    "SAML service provider is disabled",
                    ctx,
                )
                .await;
        }

        // 3. ACS URL: AuthnRequest が指定した場合は登録値との完全一致を要求する（未検証の
        //    送信先へアサーションを送らない）。未指定なら登録値を使う。
        if let Some(requested_acs) = parsed.acs_url.as_deref() {
            if requested_acs != provider.acs_url {
                return self
                    .reject(
                        tenant,
                        Some(&parsed.issuer),
                        "AssertionConsumerServiceURL does not match the registered ACS URL",
                        ctx,
                    )
                    .await;
            }
        }
        if parsed
            .request_id
            .as_deref()
            .is_some_and(|id| id.len() > MAX_REQUEST_ID_LEN)
        {
            return self
                .reject(
                    tenant,
                    Some(&parsed.issuer),
                    "AuthnRequest ID is too long",
                    ctx,
                )
                .await;
        }
        let relay_state = cmd.relay_state.filter(|s| !s.is_empty());
        if relay_state
            .as_deref()
            .is_some_and(|s| s.len() > MAX_RELAY_STATE_LEN)
        {
            return self
                .reject(tenant, Some(&parsed.issuer), "RelayState is too long", ctx)
                .await;
        }

        // 4. 進行状態を作成し、単回ハンドルで web へハンドオフする（ADR-0018 決定 2 と同方式）。
        let now = self.clock.now();
        let handle = crypto::random_hex(32);
        let request = SamlSsoRequest {
            id: crypto::random_hex(32),
            tenant_id: tenant.tenant_id(),
            service_provider_id: provider.id,
            sp_entity_id: provider.entity_id.clone(),
            acs_url: provider.acs_url.clone(),
            request_id: parsed.request_id,
            relay_state,
            handle_hash: Some(crypto::sha256_hex(&handle)),
            handle_expires_at: Some(now + Duration::seconds(HANDLE_TTL_SECS)),
            expires_at: now + self.request_ttl,
            created_at: now,
        };
        if let Err(e) = self.requests.create(&request).await {
            return SamlBeginOutcome::Internal(e.to_string());
        }

        SamlBeginOutcome::HandoffToWeb { handle }
    }

    /// web ハンドオフの再開。SSO が有効なら署名付き SAML Response を発行し、無ければ
    /// ログイン誘導（`LoginRequired`）を返す。
    pub async fn resume(
        &self,
        tenant: TenantContext,
        cmd: SamlResumeCommand,
        ctx: &RequestContext,
    ) -> SamlResumeOutcome {
        let now = self.clock.now();

        // 1. 進行状態の解決。初回はハンドルを単回消費し、ログイン後の再開は行 id で引く。
        let request = if let Some(handle) = cmd.handle.as_deref().filter(|h| !h.is_empty()) {
            let handle_hash = crypto::sha256_hex(handle);
            let request = match self
                .requests
                .find_by_handle(tenant.tenant_id(), &handle_hash)
                .await
            {
                Ok(Some(r)) => r,
                Ok(None) => return SamlResumeOutcome::Expired,
                Err(e) => return SamlResumeOutcome::Internal(e.to_string()),
            };
            if !request.handle_is_valid_at(now) || request.is_expired_at(now) {
                return SamlResumeOutcome::Expired;
            }
            match self
                .requests
                .consume_handle(&request.id, &handle_hash)
                .await
            {
                Ok(true) => {}
                // 並行する交換に負けた・再利用 → 単回使用として拒否する。
                Ok(false) => return SamlResumeOutcome::Expired,
                Err(e) => return SamlResumeOutcome::Internal(e.to_string()),
            }
            request
        } else if let Some(id) = cmd.saml_request_id.as_deref().filter(|s| !s.is_empty()) {
            match self.requests.find_by_id(tenant.tenant_id(), id).await {
                Ok(Some(r)) if !r.is_expired_at(now) => r,
                Ok(_) => return SamlResumeOutcome::Expired,
                Err(e) => return SamlResumeOutcome::Internal(e.to_string()),
            }
        } else {
            return SamlResumeOutcome::Expired;
        };

        // 2. SSO 復元（OIDC と共通の判定。メンバーシップ検証を含む）。
        let restored = match cmd.sso_session_id.as_deref().filter(|s| !s.is_empty()) {
            Some(session_id) => match self.sso_restorer.try_resume(tenant, session_id, ctx).await {
                Ok(restored) => restored,
                Err(e) => {
                    tracing::error!(error = %e, "failed to check SSO session for SAML SSO");
                    // SSO 確認失敗は致命ではない。ログインへフォールバックする。
                    None
                }
            },
            None => None,
        };
        let Some(restored) = restored else {
            return SamlResumeOutcome::LoginRequired {
                saml_request_id: request.id,
            };
        };

        // 3. SP を再解決する（フロー中の削除・無効化を SSO 成立後にも尊重する）。
        let provider = match self
            .service_providers
            .find_by_id(tenant.tenant_id(), request.service_provider_id)
            .await
        {
            Ok(Some(p)) if p.enabled => p,
            Ok(_) => {
                let _ = self.requests.delete(&request.id).await;
                return SamlResumeOutcome::Expired;
            }
            Err(e) => return SamlResumeOutcome::Internal(e.to_string()),
        };

        // 4. 進行状態を原子的に消費（クレーム）してから応答を発行する。同じ `saml_request_id` の
        //    並行 resume は片方だけが削除（1 行）に成功し、負けた側は Expired になる
        //    （1 つの AuthnRequest に対する成功アサーションの二重発行を防ぐ）。
        match self.requests.delete(&request.id).await {
            Ok(true) => {}
            Ok(false) => return SamlResumeOutcome::Expired,
            Err(e) => return SamlResumeOutcome::Internal(e.to_string()),
        }
        match self
            .issue_response(tenant, &request, &provider, restored.user_id, restored, ctx)
            .await
        {
            Ok(saml_response) => SamlResumeOutcome::Completed {
                acs_url: request.acs_url,
                saml_response,
                relay_state: request.relay_state,
            },
            // クレーム後の失敗は進行状態が消費済みのため再開できない（SP からやり直す）。
            Err(e) => SamlResumeOutcome::Internal(e),
        }
    }

    /// 署名付き SAML Response（base64）を組み立てる。
    async fn issue_response(
        &self,
        tenant: TenantContext,
        request: &SamlSsoRequest,
        provider: &SamlServiceProvider,
        user_id: uuid::Uuid,
        restored: crate::application::sso_restore::RestoredSso,
        ctx: &RequestContext,
    ) -> Result<String, String> {
        let user = match self.users.find_by_id(user_id).await {
            Ok(Some(user)) => user,
            Ok(None) => return Err("SSO user not found".to_string()),
            Err(e) => return Err(e.to_string()),
        };

        // NameID: SP 登録の Format に従う。emailAddress はメール、それ以外（persistent 等）は
        // 外部公開サブジェクト識別子（`sub`。OIDC の `sub` と同一値）を使う。
        let name_id = if provider.name_id_format.contains("emailAddress") {
            user.email.clone()
        } else {
            user.sub.to_string()
        };

        let active_key = self
            .keys
            .active_signing_key()
            .await
            .map_err(|e| format!("no active signing key: {e}"))?;
        let signer = SamlSigner::from_pem(&active_key.algorithm, &active_key.private_pem)
            .map_err(|e| e.to_string())?;

        let now = self.clock.now();
        let input = SamlResponseInput {
            response_id: &generate_saml_id(),
            assertion_id: &generate_saml_id(),
            issued_at: now,
            idp_entity_id: &tenant_issuer(&self.base_issuer, tenant.tenant_id()),
            sp_entity_id: &request.sp_entity_id,
            acs_url: &request.acs_url,
            in_response_to: request.request_id.as_deref(),
            name_id: &name_id,
            name_id_format: &provider.name_id_format,
            authn_instant: restored.auth_time,
            session_index: &format!("_{}", restored.session_hash),
            not_on_or_after: now + Duration::seconds(ASSERTION_TTL_SECS),
            email: Some(&user.email),
        };
        let xml = build_signed_response_xml(&input, &signer).map_err(|e| e.to_string())?;

        self.audit
            .record(
                AuditEventType::SamlResponseIssued,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(user.id),
                Some(&request.sp_entity_id),
                None,
                ctx,
            )
            .await;

        Ok(STANDARD.encode(xml))
    }

    /// AuthnRequest の拒否を監査記録して 400 応答を返す（未登録 SP の探索も痕跡に残す）。
    async fn reject(
        &self,
        tenant: TenantContext,
        sp_entity_id: Option<&str>,
        reason: &str,
        ctx: &RequestContext,
    ) -> SamlBeginOutcome {
        self.audit
            .record(
                AuditEventType::SamlResponseIssued,
                AuditResult::Failure,
                Some(tenant.tenant_id()),
                None,
                sp_entity_id,
                Some(reason),
                ctx,
            )
            .await;
        SamlBeginOutcome::BadRequest {
            reason: reason.to_string(),
        }
    }
}
