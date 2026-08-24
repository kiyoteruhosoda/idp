//! api への HTTP クライアント（ADR-0007）。
//!
//! web は DB を持たず、データ取得/操作はすべて api の HTTP エンドポイント越しに行う。本モジュールは
//! その唯一の出入口。内部認証（`/internal/authenticate*`）はサービス認証トークン（`X-Internal-Auth-Token`）
//! を付与して呼ぶ。DTO は `idp-contracts` で api と共有し、コンパイル時に契約整合を保証する。
//!
//! `/admin/*`（JSON 管理 API）はテナント経路（`/{tenant_id}/admin/*`。ADR-0009 §6）で呼ぶ。
//! テナント id は web の経路（`crate::tenant::WebTenant`）から呼び出し側が明示的に渡す（MT13）。

use crate::admin_dto::{
    ApiErrorBody, AuditLogView, ClientCreatedView, ClientListView, ClientSecretView, ClientView,
    InvitationCreatedView, MemberListView, UserCreatedView,
};
use idp_contracts::admin::{
    AuthenticationPoliciesResponse, AuthenticationPolicyResponse,
    AuthenticationPolicyUpsertRequest, AvailablePermissionsResponse, ClientStatusResponse,
    SamlIdpMetadataImportResponse, SamlServiceProviderRegisterRequest, SamlServiceProviderResponse,
    SamlServiceProviderUpdateRequest, SamlSpMetadataImportResponse, UserPermissionsResponse,
    UserSummaryResponse, WhoamiResponse,
};
use idp_contracts::application_log::{
    ApplicationLogEntryResponse, ApplicationLogIngestRequest, ApplicationLogIngestResponse,
    ApplicationLogPayload,
};
use idp_contracts::auth::{
    InternalAdminAuthenticateRequest, InternalAdminAuthenticateResponse,
    InternalAdminChangePasswordRequest, InternalAdminChangePasswordResponse,
    InternalAuthenticateRequest, InternalAuthenticateResponse,
    InternalAuthorizeLoginContextRequest, InternalAuthorizeLoginContextResponse,
    InternalAuthorizeResumeRequest, InternalAuthorizeResumeResponse, InternalChangePasswordRequest,
    InternalChangePasswordResponse, InternalConsentApproveRequest, InternalConsentApproveResponse,
    InternalConsentDenyRequest, InternalConsentDenyResponse, InternalConsentInfoResponse,
    InternalLogoutRequest, InternalPasskeyDeleteRequest, InternalPasskeyDeleteResponse,
    InternalPasskeyListRequest, InternalPasskeyListResponse, InternalPasskeyLoginBeginRequest,
    InternalPasskeyLoginBeginResponse, InternalPasskeyLoginCompleteRequest,
    InternalPasskeyLoginCompleteResponse, InternalPasskeyRegisterBeginRequest,
    InternalPasskeyRegisterBeginResponse, InternalPasskeyRegisterCompleteRequest,
    InternalPasskeyRegisterCompleteResponse, InternalPasswordResetCompleteRequest,
    InternalPasswordResetCompleteResponse, InternalPasswordResetRequestRequest,
    InternalPasswordResetRequestResponse, InternalPortalAuthenticateRequest,
    InternalPortalAuthenticateResponse, InternalPortalChangePasswordRequest,
    InternalPortalChangePasswordResponse, InternalPortalMfaRequest, InternalPortalMfaResponse,
    InternalRpLogoutRequest, InternalRpLogoutResponse, InternalSamlResumeRequest,
    InternalSamlResumeResponse, InternalTotpConfirmRequest, InternalTotpConfirmResponse,
    InternalTotpDeleteRequest, InternalTotpDeleteResponse, InternalTotpSetupRequest,
    InternalTotpSetupResponse, InternalVerifyTotpRequest, InternalVerifyTotpResponse,
    UNKNOWN_TENANT_ERROR_CODE,
};
use idp_contracts::runtime_settings::{
    SharedRuntimeSettingsResponse, SHARED_RUNTIME_SETTINGS_PATH,
};
use idp_contracts::version::SchemaVersionInfo;
use reqwest::Method;
use std::collections::HashMap;

/// SSO セッション Cookie 名。api へ転送する `Cookie` ヘッダの組み立てに使う（名前の契約は
/// `idp_contracts::cookies` に単一定義してあり、ここで再定義しない）。
use idp_contracts::cookies::SSO_SESSION_COOKIE;

/// サービス認証トークンのヘッダ名（api 側 `require_service_token` と一致させる）。
const SERVICE_TOKEN_HEADER: &str = "x-internal-auth-token";
/// correlation_id（requestId）の伝播ヘッダ名（api 側 correlation ミドルウェアと一致させる）。
const REQUEST_ID_HEADER: &str = "x-request-id";

/// メール検証リンク消費（SEC6b）の結果。
pub enum VerifyEmailResult {
    /// `email_verified` を立てた。
    Verified,
    /// トークンが無効・期限切れ・使用済み・別テナント。
    InvalidOrExpired,
}

/// `/internal/*` 呼び出しの失敗（MT28）。
///
/// `/internal/*` はテナントプレフィクスを持たないため api の `TenantResolver` middleware を
/// 通らず、テナントの実在・状態は本文の `tenant_id` を見て api が判定する（ADR-0009 §8）。
/// **その拒否だけを他の失敗と区別する。** 区別しないと、URL のテナント ID が誤っているだけの
/// 要求まで「web の実装/構成エラー」として 502 になり、テナント経路の他の応答（404）と揃わない。
pub enum InternalCallError {
    /// api がテナントを解決できなかった（不存在・`DISABLED`）。呼び出し側は 404 の画面へ倒す。
    UnknownTenant,
    /// それ以外 —— api へ到達できない、応答を復号できない、想定外のステータス。
    /// 利用者の入力では起こらない（web の実装/構成エラーか api の障害）ため 502 に倒す。
    Failed(String),
}

impl InternalCallError {
    fn failed(message: impl Into<String>) -> Self {
        Self::Failed(message.into())
    }
}

/// 運用ログ向けの表現（運用言語＝英語。`CLAUDE.md`「多言語化の対象範囲」）。
impl std::fmt::Display for InternalCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownTenant => write!(f, "unknown or disabled tenant"),
            Self::Failed(m) => write!(f, "{m}"),
        }
    }
}

impl std::fmt::Debug for InternalCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for InternalCallError {}

/// api のエラー本文が「テナントを解決できなかった」を表すか（MT28）。
///
/// 判別は `contracts` が単一定義する [`UNKNOWN_TENANT_ERROR_CODE`] との一致で行う。人間向けの
/// 説明文を見ないのは、文言を直した瞬間に静かに壊れるためである。本文が JSON として読めない
/// ときは「その他の失敗」に倒す（fail-safe。誤って 404 の画面を出さない）。
fn is_unknown_tenant_error(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error")?.as_str().map(str::to_string))
        .is_some_and(|code| code == UNKNOWN_TENANT_ERROR_CODE)
}

/// `/admin/*` 呼び出しの失敗を web の画面挙動へ写すためのエラー（ADR-0007 §4）。
pub enum AdminApiError {
    /// 未認証・SSO 期限切れ（401）→ ログイン画面へ誘導。
    Unauthorized,
    /// 権限不足（403）→ 403 画面。
    Forbidden,
    /// 不存在（404）。
    NotFound,
    /// バリデーションエラー（400）。メッセージを表示する。
    Validation(String),
    /// 競合（409）。メッセージを表示する。
    Conflict(String),
    /// ネットワーク/デコード/想定外ステータス。
    Transport(String),
}

/// 運用ログ向けの表現（運用言語＝英語。`CLAUDE.md`「多言語化の対象範囲」）。
///
/// 画面へ出す文言は各ハンドラが翻訳キーから解決する。ここが返すのは**ログに出す理由**で、
/// 各ハンドラで同じ `match` を書き直さないために型側へ置く。
impl std::fmt::Display for AdminApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "unauthorized"),
            Self::Forbidden => write!(f, "forbidden"),
            Self::NotFound => write!(f, "not_found"),
            Self::Validation(m) => write!(f, "validation: {m}"),
            Self::Conflict(m) => write!(f, "conflict: {m}"),
            Self::Transport(m) => write!(f, "transport: {m}"),
        }
    }
}

/// 管理者の SSO Cookie を api の `/admin/*`（`RequirePerms<IdpAdmin>`）へ転送した結果（ADR-0007 §4）。
pub enum AdminSession {
    /// 有効な SSO ＋ テナント admin 権限（`idp.tenant.admin`／`idp.system.admin`）保有。
    /// 管理コンソールのヘッダに出す文脈（管理者の表示ラベルと操作中テナントの表示名）を返す。
    Authenticated(AdminIdentity),
    /// 未認証・SSO 期限切れ（ログイン画面へ誘導する）。
    Unauthenticated,
    /// 認証済みだがテナント admin 権限なし（403 画面）。
    Forbidden,
    /// api がテナントを解決できなかった（404）。経路の `{tenant_id}` が未知・`DISABLED`・UUID 不正の
    /// いずれか（api の `resolve_tenant` はどれも 404 に倒す）。web は UUID 形式しか検証しないため、
    /// 実在しないテナントの管理コンソール URL はここに落ちる。
    NotFound,
    /// api 呼び出し失敗（構成/障害）。
    Error,
}

/// whoami の非 200 応答をセッション状態へ写す。200（本文のデコードを伴う）は呼び出し側で扱う。
///
/// 404 を `Error` に含めない（＝ 502 に倒さない）のが要点。存在しないテナントの URL はゲートウェイ
/// 障害ではなく「そのページは無い」であり、画面も 404 を出す必要がある。
fn admin_session_for_status(status: reqwest::StatusCode) -> AdminSession {
    match status {
        reqwest::StatusCode::UNAUTHORIZED => AdminSession::Unauthenticated,
        reqwest::StatusCode::FORBIDDEN => AdminSession::Forbidden,
        reqwest::StatusCode::NOT_FOUND => AdminSession::NotFound,
        _ => AdminSession::Error,
    }
}

/// 認証済み管理者の身元（管理コンソール共通ヘッダの表示に使う）。
#[derive(Debug, Clone)]
pub struct AdminIdentity {
    /// 管理者の表示ラベル（表示名 → ログイン識別子 → 内部 ID）。
    pub label: String,
    /// 操作中テナントの表示名。api が返さなかった場合のみ `None`。
    pub tenant_name: Option<String>,
}

/// whoami の応答をヘッダ表示の文脈へ写す。
fn admin_identity(mut w: WhoamiResponse) -> AdminIdentity {
    let tenant_name = non_empty(w.tenant_name.take());
    AdminIdentity {
        label: admin_display_label(w),
        tenant_name,
    }
}

/// 管理コンソールのヘッダに出す表示ラベルを決める。表示名（`name`）→ ログイン識別子
/// （`preferred_username`）→ 内部 ID（`user_id`）の順で、空でない最初の値を採用する。
fn admin_display_label(w: WhoamiResponse) -> String {
    non_empty(w.name)
        .or_else(|| non_empty(w.preferred_username))
        .unwrap_or(w.user_id)
}

/// 空白のみの値を「未設定」として扱う。
fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// api への HTTP クライアント。`reqwest::Client` は接続プールを内包するため clone は安価。
#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    base_url: String,
    service_token: String,
    /// api へ引き継ぐ表示言語（`Accept-Language`）。`None` なら送らず、api は既定 `ja` を使う。
    ///
    /// 表示言語を決めるのは web で、api は `Accept-Language` しか見ない（`CLAUDE.md`「国際化」）。
    /// web が決めた言語を載せることで、画面と api のエラーメッセージが同じ言語になる。
    /// **Cookie・`lang` クエリは api へ送らない**（api がそれらを見ないための境界）。
    accept_language: Option<&'static str>,
}

impl ApiClient {
    pub fn new(base_url: impl Into<String>, service_token: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into(),
            service_token: service_token.into(),
            accept_language: None,
        }
    }

    /// 表示言語を引き継いだクライアントを返す（MT20）。以降の api 呼び出しへ `Accept-Language` を
    /// 付与し、api のエラーメッセージを画面と同じ言語で受け取る。`reqwest::Client` は Arc 内包の
    /// ため clone は安価で、リクエストごとに作ってよい。
    pub fn for_locale(&self, locale: crate::i18n::Locale) -> Self {
        Self {
            accept_language: Some(locale.as_tag()),
            ..self.clone()
        }
    }

    /// `Accept-Language` を（決まっていれば）付与する。
    fn with_language(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.accept_language {
            Some(tag) => request.header(reqwest::header::ACCEPT_LANGUAGE, tag),
            None => request,
        }
    }

    /// SAML IdP メタデータを api から取得する。
    ///
    /// ブラウザを api オリジンへ直接遷移させず、web が提供するダウンロード用ユースケースから
    /// 利用する。api との通信経路は本クライアントへ集約し、presentation 層へ HTTP の詳細を
    /// 漏らさない。
    pub async fn fetch_saml_idp_metadata(
        &self,
        correlation_id: &str,
        tenant_id: &str,
    ) -> anyhow::Result<String> {
        self.http
            .get(format!("{}/{tenant_id}/saml/metadata", self.base_url))
            .header(REQUEST_ID_HEADER, correlation_id)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
            .map_err(Into::into)
    }

    /// 認可フローの再開（`POST /internal/authorize/resume`、ADR-0018 決定 2）。`/authorize` からの
    /// ハンドオフで受け取った単回ハンドルと自ドメインの SSO Cookie 値を渡し、SSO 判定・code 発行
    /// までを api に委ねる。
    pub async fn authorize_resume(
        &self,
        correlation_id: &str,
        req: &InternalAuthorizeResumeRequest,
    ) -> Result<InternalAuthorizeResumeResponse, InternalCallError> {
        self.post_internal("/internal/authorize/resume", correlation_id, req)
            .await
    }

    /// ログイン画面の文脈（`POST /internal/authorize/login-context`。G12）。進行中の認可要求が
    /// 持ち込んだ `login_hint` / `ui_locales` を `auth_session_id` から引き直す。
    pub async fn authorize_login_context(
        &self,
        correlation_id: &str,
        req: &InternalAuthorizeLoginContextRequest,
    ) -> Result<InternalAuthorizeLoginContextResponse, InternalCallError> {
        self.post_internal("/internal/authorize/login-context", correlation_id, req)
            .await
    }

    /// SAML SSO フローの再開（`POST /internal/saml/resume`）。`/saml/sso` からのハンドオフで
    /// 受け取った単回ハンドル（またはログイン後の `saml_request_id`）と自ドメインの SSO Cookie 値を
    /// 渡し、SSO 判定・署名付き SAML Response の発行までを api に委ねる。
    pub async fn saml_resume(
        &self,
        correlation_id: &str,
        req: &InternalSamlResumeRequest,
    ) -> Result<InternalSamlResumeResponse, InternalCallError> {
        self.post_internal("/internal/saml/resume", correlation_id, req)
            .await
    }

    /// RP-initiated logout（`POST /internal/logout/rp`、ADR-0018 決定 2）。SSO 失効・back-channel
    /// 通知・post-logout リダイレクト URL の組み立てを api に委ねる（Cookie 破棄は web が行う）。
    pub async fn rp_logout(
        &self,
        correlation_id: &str,
        req: &InternalRpLogoutRequest,
    ) -> Result<InternalRpLogoutResponse, InternalCallError> {
        self.post_internal("/internal/logout/rp", correlation_id, req)
            .await
    }

    /// OIDC ログイン認証（`POST /internal/authenticate`）。
    pub async fn authenticate(
        &self,
        correlation_id: &str,
        req: &InternalAuthenticateRequest,
    ) -> Result<InternalAuthenticateResponse, InternalCallError> {
        self.post_internal("/internal/authenticate", correlation_id, req)
            .await
    }

    /// 強制パスワード変更（`POST /internal/change-password`、ADR-0009 §5）。
    pub async fn change_password(
        &self,
        correlation_id: &str,
        req: &InternalChangePasswordRequest,
    ) -> Result<InternalChangePasswordResponse, InternalCallError> {
        self.post_internal("/internal/change-password", correlation_id, req)
            .await
    }

    /// 管理コンソール認証（`POST /internal/authenticate/admin`）。
    pub async fn authenticate_admin(
        &self,
        correlation_id: &str,
        req: &InternalAdminAuthenticateRequest,
    ) -> Result<InternalAdminAuthenticateResponse, InternalCallError> {
        self.post_internal("/internal/authenticate/admin", correlation_id, req)
            .await
    }

    /// エンドユーザー・ポータル認証（`POST /internal/authenticate/portal`）。
    pub async fn authenticate_portal(
        &self,
        correlation_id: &str,
        req: &InternalPortalAuthenticateRequest,
    ) -> Result<InternalPortalAuthenticateResponse, InternalCallError> {
        self.post_internal("/internal/authenticate/portal", correlation_id, req)
            .await
    }

    /// ポータルの TOTP 検証（`POST /internal/authenticate/portal/mfa`）。
    pub async fn authenticate_portal_mfa(
        &self,
        correlation_id: &str,
        req: &InternalPortalMfaRequest,
    ) -> Result<InternalPortalMfaResponse, InternalCallError> {
        self.post_internal("/internal/authenticate/portal/mfa", correlation_id, req)
            .await
    }

    /// ポータルの強制パスワード変更（`POST /internal/authenticate/portal/change-password`、ADR-0009 §5）。
    pub async fn authenticate_portal_change_password(
        &self,
        correlation_id: &str,
        req: &InternalPortalChangePasswordRequest,
    ) -> Result<InternalPortalChangePasswordResponse, InternalCallError> {
        self.post_internal(
            "/internal/authenticate/portal/change-password",
            correlation_id,
            req,
        )
        .await
    }

    /// 管理コンソールの強制パスワード変更（`POST /internal/authenticate/admin/change-password`）。
    pub async fn admin_change_password(
        &self,
        correlation_id: &str,
        req: &InternalAdminChangePasswordRequest,
    ) -> Result<InternalAdminChangePasswordResponse, InternalCallError> {
        self.post_internal(
            "/internal/authenticate/admin/change-password",
            correlation_id,
            req,
        )
        .await
    }

    /// パスワードリセット要求（`POST /internal/password-reset/request`。MT18）。
    pub async fn password_reset_request(
        &self,
        correlation_id: &str,
        req: &InternalPasswordResetRequestRequest,
    ) -> Result<InternalPasswordResetRequestResponse, InternalCallError> {
        self.post_internal("/internal/password-reset/request", correlation_id, req)
            .await
    }

    /// パスワードリセット実行（`POST /internal/password-reset/complete`。MT18）。
    pub async fn password_reset_complete(
        &self,
        correlation_id: &str,
        req: &InternalPasswordResetCompleteRequest,
    ) -> Result<InternalPasswordResetCompleteResponse, InternalCallError> {
        self.post_internal("/internal/password-reset/complete", correlation_id, req)
            .await
    }

    /// メール検証リンクの消費（`POST /{tenant_id}/auth/verify-email`。SEC6b）。公開エンドポイントの
    /// ため service token・SSO は不要（平文トークン自体が capability）。
    pub async fn verify_email(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        token: &str,
    ) -> anyhow::Result<VerifyEmailResult> {
        let response = self
            .http
            .post(format!("{}/{}/auth/verify-email", self.base_url, tenant_id))
            .header(REQUEST_ID_HEADER, correlation_id)
            .json(&serde_json::json!({ "token": token }))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("request to api /auth/verify-email failed: {e}"))?;
        match response.status() {
            s if s.is_success() => Ok(VerifyEmailResult::Verified),
            reqwest::StatusCode::BAD_REQUEST => Ok(VerifyEmailResult::InvalidOrExpired),
            other => anyhow::bail!("api /auth/verify-email returned status {other}"),
        }
    }

    /// ログアウト（`POST /internal/logout`）。api 側で SSO セッションを失効させる（Cookie 失効は web）。
    pub async fn logout(
        &self,
        correlation_id: &str,
        req: &InternalLogoutRequest,
    ) -> anyhow::Result<()> {
        let response = self
            .http
            .post(format!("{}/internal/logout", self.base_url))
            .header(SERVICE_TOKEN_HEADER, &self.service_token)
            .header(REQUEST_ID_HEADER, correlation_id)
            .json(req)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("request to api /internal/logout failed: {e}"))?;
        if !response.status().is_success() {
            anyhow::bail!("api /internal/logout returned status {}", response.status());
        }
        Ok(())
    }

    /// 同意画面情報取得（`GET /internal/consent-info`）。`tenant_id` はフローのテナント（必須。
    /// api は未指定・不正を 400 で拒否する）。
    pub async fn consent_info(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        auth_session_id: &str,
    ) -> Result<InternalConsentInfoResponse, InternalCallError> {
        let response = self
            .http
            .get(format!("{}/internal/consent-info", self.base_url))
            .header(SERVICE_TOKEN_HEADER, &self.service_token)
            .header(REQUEST_ID_HEADER, correlation_id)
            .query(&[
                ("tenant_id", tenant_id),
                ("auth_session_id", auth_session_id),
            ])
            .send()
            .await
            .map_err(|e| {
                InternalCallError::failed(format!(
                    "request to api /internal/consent-info failed: {e}"
                ))
            })?;
        // `/internal/*` で唯一の GET。POST 側（`post_internal`）と同じくテナント解決の失敗を
        // 区別する（区別しないと、この画面だけ不存在テナントで 502 のまま残る）。
        let status = response.status();
        if !status.is_success() {
            if status == reqwest::StatusCode::BAD_REQUEST
                && is_unknown_tenant_error(&response.text().await.unwrap_or_default())
            {
                return Err(InternalCallError::UnknownTenant);
            }
            return Err(InternalCallError::failed(format!(
                "api /internal/consent-info returned unexpected status {status}"
            )));
        }
        response
            .json::<InternalConsentInfoResponse>()
            .await
            .map_err(|e| {
                InternalCallError::failed(format!("failed to decode consent-info response: {e}"))
            })
    }

    /// 同意承認（`POST /internal/consent/approve`）。
    pub async fn consent_approve(
        &self,
        correlation_id: &str,
        req: &InternalConsentApproveRequest,
    ) -> Result<InternalConsentApproveResponse, InternalCallError> {
        self.post_internal("/internal/consent/approve", correlation_id, req)
            .await
    }

    /// 同意拒否（`POST /internal/consent/deny`）。
    pub async fn consent_deny(
        &self,
        correlation_id: &str,
        req: &InternalConsentDenyRequest,
    ) -> Result<InternalConsentDenyResponse, InternalCallError> {
        self.post_internal("/internal/consent/deny", correlation_id, req)
            .await
    }

    /// TOTP セットアップ開始（`POST /internal/mfa/totp/setup`）。QR URI と生シークレットを返す。
    pub async fn totp_setup(
        &self,
        correlation_id: &str,
        req: &InternalTotpSetupRequest,
    ) -> Result<InternalTotpSetupResponse, InternalCallError> {
        self.post_internal("/internal/mfa/totp/setup", correlation_id, req)
            .await
    }

    /// TOTP 確認（`POST /internal/mfa/totp/confirm`）。6 桁コードで有効化する。
    pub async fn totp_confirm(
        &self,
        correlation_id: &str,
        req: &InternalTotpConfirmRequest,
    ) -> Result<InternalTotpConfirmResponse, InternalCallError> {
        self.post_internal("/internal/mfa/totp/confirm", correlation_id, req)
            .await
    }

    /// TOTP 削除（`POST /internal/mfa/totp/delete`）。MFA を無効化する。
    pub async fn totp_delete(
        &self,
        correlation_id: &str,
        req: &InternalTotpDeleteRequest,
    ) -> Result<InternalTotpDeleteResponse, InternalCallError> {
        self.post_internal("/internal/mfa/totp/delete", correlation_id, req)
            .await
    }

    /// ログインフロー TOTP 検証（`POST /internal/mfa/totp/verify`）。
    pub async fn verify_totp(
        &self,
        correlation_id: &str,
        req: &InternalVerifyTotpRequest,
    ) -> Result<InternalVerifyTotpResponse, InternalCallError> {
        self.post_internal("/internal/mfa/totp/verify", correlation_id, req)
            .await
    }

    // ─── Passkey（WebAuthn）API ───────────────────────────────────────────

    /// Passkey 登録開始（`POST /internal/passkey/register/begin`）。
    pub async fn passkey_register_begin(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyRegisterBeginRequest,
    ) -> Result<InternalPasskeyRegisterBeginResponse, InternalCallError> {
        self.post_internal("/internal/passkey/register/begin", correlation_id, req)
            .await
    }

    /// Passkey 登録完了（`POST /internal/passkey/register/complete`）。
    pub async fn passkey_register_complete(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyRegisterCompleteRequest,
    ) -> Result<InternalPasskeyRegisterCompleteResponse, InternalCallError> {
        self.post_internal("/internal/passkey/register/complete", correlation_id, req)
            .await
    }

    /// Passkey 削除（`POST /internal/passkey/delete`）。
    pub async fn passkey_delete(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyDeleteRequest,
    ) -> Result<InternalPasskeyDeleteResponse, InternalCallError> {
        self.post_internal("/internal/passkey/delete", correlation_id, req)
            .await
    }

    /// 登録済み Passkey 一覧（`POST /internal/passkey/list`）。
    pub async fn passkey_list(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyListRequest,
    ) -> Result<InternalPasskeyListResponse, InternalCallError> {
        self.post_internal("/internal/passkey/list", correlation_id, req)
            .await
    }

    /// Passkey 認証開始（`POST /internal/passkey/login/begin`）。
    pub async fn passkey_login_begin(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyLoginBeginRequest,
    ) -> Result<InternalPasskeyLoginBeginResponse, InternalCallError> {
        self.post_internal("/internal/passkey/login/begin", correlation_id, req)
            .await
    }

    /// Passkey 認証完了（`POST /internal/passkey/login/complete`）。
    pub async fn passkey_login_complete(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyLoginCompleteRequest,
    ) -> Result<InternalPasskeyLoginCompleteResponse, InternalCallError> {
        self.post_internal("/internal/passkey/login/complete", correlation_id, req)
            .await
    }

    /// 管理者の SSO Cookie を api の `GET /{tenant_id}/admin/whoami` へ転送し、認証状態と身元を得る
    /// （ADR-0007 §4・ADR-0009 §6）。
    pub async fn admin_whoami(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso_session_id: &str,
    ) -> AdminSession {
        let response = match self
            .http
            .get(format!("{}/{}/admin/whoami", self.base_url, tenant_id))
            .header(REQUEST_ID_HEADER, correlation_id)
            .header(
                reqwest::header::COOKIE,
                format!("{SSO_SESSION_COOKIE}={sso_session_id}"),
            )
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "admin whoami call to api failed");
                return AdminSession::Error;
            }
        };
        match response.status() {
            reqwest::StatusCode::OK => match response.json::<WhoamiResponse>().await {
                Ok(w) => AdminSession::Authenticated(admin_identity(w)),
                Err(e) => {
                    tracing::error!(error = %e, "failed to decode whoami response");
                    AdminSession::Error
                }
            },
            other => {
                let session = admin_session_for_status(other);
                if matches!(session, AdminSession::Error) {
                    tracing::error!(status = %other, "unexpected whoami status from api");
                }
                session
            }
        }
    }

    // ── 管理コンソール → JSON 管理 API（`/{tenant_id}/admin/*`、SSO Cookie 転送）───────────────

    /// クライアント一覧の 1 ページ分（`GET /admin/clients`。G7）。ページングは api（DB）側で行う。
    pub async fn list_clients(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        query: &[(&str, String)],
    ) -> Result<ClientListView, AdminApiError> {
        self.admin_get_with_query(tenant_id, "/admin/clients", correlation_id, sso, query)
            .await
    }

    /// 単一クライアント（`GET /admin/clients/{id}`）。
    pub async fn get_client(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        client_id: &str,
    ) -> Result<ClientView, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            &format!("/admin/clients/{client_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// クライアント作成（`POST /admin/clients`）。
    pub async fn create_client(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        body: serde_json::Value,
    ) -> Result<ClientCreatedView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/clients",
            correlation_id,
            sso,
            Some(body),
        )
        .await
    }

    /// クライアント部分更新（`PATCH /admin/clients/{id}`）。
    pub async fn update_client(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        client_id: &str,
        body: serde_json::Value,
    ) -> Result<ClientView, AdminApiError> {
        self.admin_send(
            Method::PATCH,
            tenant_id,
            &format!("/admin/clients/{client_id}"),
            correlation_id,
            sso,
            Some(body),
        )
        .await
    }

    /// secret 再発行（`POST /admin/clients/{id}/secret`）。
    pub async fn rotate_client_secret(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        client_id: &str,
    ) -> Result<ClientSecretView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/clients/{client_id}/secret"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    // ── 利用者・権限（管理コンソールの権限画面）─────────────────────────────────

    /// 利用者取得（`GET /admin/users/{id}`）。
    pub async fn get_user(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<UserSummaryResponse, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            &format!("/admin/users/{user_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// 利用者作成（`POST /admin/users`）。パスワードは自動生成され `generated_password` を一度だけ返す。
    pub async fn create_user(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        body: serde_json::Value,
    ) -> Result<UserCreatedView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/users",
            correlation_id,
            sso,
            Some(body),
        )
        .await
    }

    /// 付与可能な権限コード（`GET /admin/permissions`）。
    pub async fn available_permissions(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<AvailablePermissionsResponse, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/permissions",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// 保有権限一覧（`GET /admin/users/{id}/permissions`）。
    pub async fn list_user_permissions(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<UserPermissionsResponse, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            &format!("/admin/users/{user_id}/permissions"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// 権限付与（`POST /admin/users/{id}/permissions`）。
    pub async fn grant_permission(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        code: &str,
    ) -> Result<UserPermissionsResponse, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/users/{user_id}/permissions"),
            correlation_id,
            sso,
            Some(serde_json::json!({ "permission_code": code })),
        )
        .await
    }

    /// 権限剥奪（`DELETE /admin/users/{id}/permissions/{code}`）。
    pub async fn revoke_permission(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        code: &str,
    ) -> Result<UserPermissionsResponse, AdminApiError> {
        self.admin_send(
            Method::DELETE,
            tenant_id,
            &format!("/admin/users/{user_id}/permissions/{code}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// 利用者の状態変更（`PATCH /admin/users/{user_id}`。ACTIVE / DISABLED）。
    pub async fn update_user_status(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        status: &str,
    ) -> Result<UserSummaryResponse, AdminApiError> {
        self.admin_send(
            Method::PATCH,
            tenant_id,
            &format!("/admin/users/{user_id}"),
            correlation_id,
            sso,
            Some(serde_json::json!({ "status": status })),
        )
        .await
    }

    /// 利用者プロフィール（メール・ログイン識別子・表示名）の更新
    /// （`PATCH /admin/users/{user_id}/profile`。MT25）。`profile` は
    /// `{ email, preferred_username, name }`（`name` は空文字で解除を意味する）。
    pub async fn update_user_profile(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        profile: serde_json::Value,
    ) -> Result<UserSummaryResponse, AdminApiError> {
        self.admin_send(
            Method::PATCH,
            tenant_id,
            &format!("/admin/users/{user_id}/profile"),
            correlation_id,
            sso,
            Some(profile),
        )
        .await
    }

    /// 利用者の削除（`DELETE /admin/users/{user_id}`。所属元が当該テナントの利用者のみ）。
    pub async fn delete_user(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/users/{user_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// 利用者のパスワード再発行（`POST /admin/users/{user_id}/password-reset`）。
    /// `generated_password` を一度だけ返す。
    pub async fn reset_user_password(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<crate::admin_dto::UserPasswordResetView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/users/{user_id}/password-reset"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// 利用者の MFA 解除（`POST /admin/users/{user_id}/mfa-reset`。MT21）。
    /// TOTP と Passkey をまとめて外し、外した内訳を返す。
    pub async fn reset_user_mfa(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<crate::admin_dto::UserMfaResetView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/users/{user_id}/mfa-reset"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// アカウントロックの即時解除（`POST /admin/users/{user_id}/unlock`。AP6）。
    /// ロック期限のクリアと失敗回数のリセットを api 側が同時に行う。
    pub async fn unlock_user(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<crate::admin_dto::UserUnlockView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/users/{user_id}/unlock"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    // ── 外部 IdP 設定・ログイン識別子（AP16。API は AP10 / AP8）────────────────

    /// 外部 IdP 設定の一覧（`GET /admin/external-idps`）。
    pub async fn list_external_idps(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<Vec<crate::admin_dto::ExternalIdpView>, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/external-idps",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// 外部 IdP 設定の作成（`POST /admin/external-idps`）。
    pub async fn create_external_idp(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        body: serde_json::Value,
    ) -> Result<crate::admin_dto::ExternalIdpView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/external-idps",
            correlation_id,
            sso,
            Some(body),
        )
        .await
    }

    /// 外部 IdP 設定の部分更新（`PATCH /admin/external-idps/{id}`）。
    pub async fn update_external_idp(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        id: &str,
        body: serde_json::Value,
    ) -> Result<crate::admin_dto::ExternalIdpView, AdminApiError> {
        self.admin_send(
            Method::PATCH,
            tenant_id,
            &format!("/admin/external-idps/{id}"),
            correlation_id,
            sso,
            Some(body),
        )
        .await
    }

    /// 外部 IdP メタデータ取り込み（`POST /admin/external-idps/import-metadata`）。AP12。
    /// 解析だけを行い、登録候補値を返す（永続化はしない）。
    pub async fn import_external_idp_metadata(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        metadata_xml: &str,
    ) -> Result<SamlIdpMetadataImportResponse, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/external-idps/import-metadata",
            correlation_id,
            sso,
            Some(serde_json::json!({ "metadata_xml": metadata_xml })),
        )
        .await
    }

    /// 外部 IdP 設定の削除（`DELETE /admin/external-idps/{id}`）。
    pub async fn delete_external_idp(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/external-idps/{id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// 利用者のログイン識別子一覧（`GET /admin/users/{user_id}/login-identifiers`）。
    pub async fn list_login_identifiers(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<Vec<crate::admin_dto::LoginIdentifierView>, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            &format!("/admin/users/{user_id}/login-identifiers"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// ログイン識別子の追加（`POST /admin/users/{user_id}/login-identifiers`）。
    pub async fn add_login_identifier(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        body: serde_json::Value,
    ) -> Result<crate::admin_dto::LoginIdentifierView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/users/{user_id}/login-identifiers"),
            correlation_id,
            sso,
            Some(body),
        )
        .await
    }

    /// ログイン識別子の有効/無効切り替え（`PATCH .../login-identifiers/{id}`）。
    pub async fn set_login_identifier_active(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        identifier_id: &str,
        is_active: bool,
    ) -> Result<crate::admin_dto::LoginIdentifierView, AdminApiError> {
        self.admin_send(
            Method::PATCH,
            tenant_id,
            &format!("/admin/users/{user_id}/login-identifiers/{identifier_id}"),
            correlation_id,
            sso,
            Some(serde_json::json!({ "is_active": is_active })),
        )
        .await
    }

    /// ログイン識別子の削除（`DELETE .../login-identifiers/{id}`）。
    pub async fn delete_login_identifier(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        identifier_id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/users/{user_id}/login-identifiers/{identifier_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    // ── メンバー・招待（ADR-0009 §3）─────────────────────────────────────────

    /// メンバー一覧（`GET /admin/members`。HOME / GUEST を問わない）。絞り込み・ページングの
    /// 条件は `(key, value)` の並びで渡す（MT22。絞り込みは api 側＝DB で行う）。
    pub async fn list_members(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        query: &[(&str, String)],
    ) -> Result<MemberListView, AdminApiError> {
        let response = self
            .with_language(
                self.http
                    .get(format!("{}/{}/admin/members", self.base_url, tenant_id))
                    .query(query)
                    .header(REQUEST_ID_HEADER, correlation_id)
                    .header(
                        reqwest::header::COOKIE,
                        format!("{SSO_SESSION_COOKIE}={sso}"),
                    ),
            )
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        Self::handle_admin_response(response, "/admin/members").await
    }

    /// ゲストメンバーシップの一時停止・再開（`PATCH /admin/members/{user_id}`。MT24）。
    /// `status` は `SUSPENDED`（停止）または `ACTIVE`（再開）。
    pub async fn update_member_status(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        status: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::PATCH,
            tenant_id,
            &format!("/admin/members/{user_id}"),
            correlation_id,
            sso,
            Some(serde_json::json!({ "status": status })),
        )
        .await
    }

    /// ゲストメンバーシップの解除（`DELETE /admin/members/{user_id}`。HOME は不可）。
    pub async fn revoke_member(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/members/{user_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// ゲスト招待の作成（`POST /admin/invitations`）。招待トークンを一度だけ返す。
    pub async fn create_invitation(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<InvitationCreatedView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/invitations",
            correlation_id,
            sso,
            Some(serde_json::json!({ "user_id": user_id })),
        )
        .await
    }

    /// 招待の承諾（`POST /{tenant_id}/invitations/accept`）。被招待者本人の SSO Cookie を転送する
    /// （管理 API ではないが、Cookie 転送・エラー写像は同じ共通処理を使う）。
    pub async fn accept_invitation(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        token: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::POST,
            tenant_id,
            "/invitations/accept",
            correlation_id,
            sso,
            Some(serde_json::json!({ "token": token })),
        )
        .await
    }

    // ── 状況確認（監査ログ・クライアント状況）─────────────────────────────────

    /// 監査ログ検索（`GET /admin/audit-logs`）。フィルタは `(key, value)` の並びで渡す。
    pub async fn search_audit_logs(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        query: &[(&str, String)],
    ) -> Result<Vec<AuditLogView>, AdminApiError> {
        let response = self
            .with_language(
                self.http
                    .get(format!("{}/{}/admin/audit-logs", self.base_url, tenant_id))
                    .query(query)
                    .header(REQUEST_ID_HEADER, correlation_id)
                    .header(
                        reqwest::header::COOKIE,
                        format!("{SSO_SESSION_COOKIE}={sso}"),
                    ),
            )
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        Self::handle_admin_response(response, "/admin/audit-logs").await
    }

    /// エラー・警告ログ検索（`GET /admin/logs`）。フィルタは `(key, value)` の並びで渡す。
    /// 参照権限は api 側が `idp.system.admin` で強制する（テナント横断の運用情報のため）。
    pub async fn search_application_logs(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        query: &[(&str, String)],
    ) -> Result<Vec<ApplicationLogEntryResponse>, AdminApiError> {
        let response = self
            .with_language(
                self.http
                    .get(format!("{}/{}/admin/logs", self.base_url, tenant_id))
                    .query(query)
                    .header(REQUEST_ID_HEADER, correlation_id)
                    .header(
                        reqwest::header::COOKIE,
                        format!("{SSO_SESSION_COOKIE}={sso}"),
                    ),
            )
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        Self::handle_admin_response(response, "/admin/logs").await
    }

    /// 自身の WARN / ERROR を api へ送って `log` テーブルへ書いてもらう（`POST /internal/logs`）。
    /// web は DB を持たないため、これがアプリケーションログを残す唯一の経路（CLAUDE.md「ログ」）。
    ///
    /// **失敗しても呼び出し側はログを出さないこと**（送信失敗のログがまた送信を誘発するため）。
    /// 受理件数を返す。
    pub async fn push_application_logs(
        &self,
        records: Vec<ApplicationLogPayload>,
    ) -> anyhow::Result<usize> {
        let response = self
            .http
            .post(format!("{}/internal/logs", self.base_url))
            .header(SERVICE_TOKEN_HEADER, &self.service_token)
            .json(&ApplicationLogIngestRequest { records })
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("api /internal/logs returned status {}", response.status());
        }
        Ok(response
            .json::<ApplicationLogIngestResponse>()
            .await?
            .accepted)
    }

    /// クライアント状況一覧（`GET /admin/clients/status`）。
    pub async fn list_client_status(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<Vec<ClientStatusResponse>, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/clients/status",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// SAML SP（クライアント）一覧（`GET /admin/saml-service-providers`）。
    pub async fn list_saml_service_providers(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<Vec<crate::admin_dto::SamlServiceProviderView>, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/saml-service-providers",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    // ── 認証ポリシー（AP1。`/admin/authentication-policies`）────────────────────────

    /// 認証ポリシー一覧（`GET /admin/authentication-policies`。priority 昇順・無効も含む）。
    pub async fn list_authentication_policies(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<AuthenticationPoliciesResponse, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/authentication-policies",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// 認証ポリシーの作成（`POST /admin/authentication-policies`）。
    pub async fn create_authentication_policy(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        body: AuthenticationPolicyUpsertRequest,
    ) -> Result<AuthenticationPolicyResponse, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/authentication-policies",
            correlation_id,
            sso,
            Some(serde_json::to_value(body).map_err(|e| AdminApiError::Transport(e.to_string()))?),
        )
        .await
    }

    /// 認証ポリシーの更新（`PUT /admin/authentication-policies/{id}`。全項目置換）。
    pub async fn update_authentication_policy(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        policy_id: &str,
        body: AuthenticationPolicyUpsertRequest,
    ) -> Result<AuthenticationPolicyResponse, AdminApiError> {
        self.admin_send(
            Method::PUT,
            tenant_id,
            &format!("/admin/authentication-policies/{policy_id}"),
            correlation_id,
            sso,
            Some(serde_json::to_value(body).map_err(|e| AdminApiError::Transport(e.to_string()))?),
        )
        .await
    }

    /// 認証ポリシーの削除（`DELETE /admin/authentication-policies/{id}`）。
    pub async fn delete_authentication_policy(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        policy_id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/authentication-policies/{policy_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// SAML SP（クライアント）登録（`POST /admin/saml-service-providers`）。
    pub async fn register_saml_service_provider(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        body: SamlServiceProviderRegisterRequest,
    ) -> Result<SamlServiceProviderResponse, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/saml-service-providers",
            correlation_id,
            sso,
            Some(serde_json::to_value(body).map_err(|e| AdminApiError::Transport(e.to_string()))?),
        )
        .await
    }

    /// SAML SP（クライアント）更新（`PUT /admin/saml-service-providers/{id}`）。
    pub async fn update_saml_service_provider(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        id: &str,
        body: SamlServiceProviderUpdateRequest,
    ) -> Result<SamlServiceProviderResponse, AdminApiError> {
        self.admin_send(
            Method::PUT,
            tenant_id,
            &format!("/admin/saml-service-providers/{id}"),
            correlation_id,
            sso,
            Some(serde_json::to_value(body).map_err(|e| AdminApiError::Transport(e.to_string()))?),
        )
        .await
    }

    /// SAML SP（クライアント）削除（`DELETE /admin/saml-service-providers/{id}`）。
    pub async fn delete_saml_service_provider(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/saml-service-providers/{id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// SP メタデータ取り込み（`POST /admin/saml-service-providers/import-metadata`）。
    pub async fn import_saml_sp_metadata(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        metadata_xml: &str,
    ) -> Result<SamlSpMetadataImportResponse, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/saml-service-providers/import-metadata",
            correlation_id,
            sso,
            Some(serde_json::json!({ "metadata_xml": metadata_xml })),
        )
        .await
    }

    // ── 署名鍵管理（K1）─────────────────────────────────────────────────────

    /// 署名鍵一覧（`GET /admin/signing-keys`）。
    pub async fn list_signing_keys(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<Vec<crate::admin_dto::SigningKeyView>, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/signing-keys",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// 新規署名鍵を生成する（`POST /admin/signing-keys`）。`algorithm` は `RS256` または `ES256`。
    pub async fn generate_signing_key(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        algorithm: &str,
    ) -> Result<crate::admin_dto::SigningKeyView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/signing-keys",
            correlation_id,
            sso,
            Some(serde_json::json!({ "algorithm": algorithm })),
        )
        .await
    }

    /// 署名鍵を退役させる（`POST /admin/signing-keys/{kid}/retire`）。
    pub async fn retire_signing_key(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        kid: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::POST,
            tenant_id,
            &format!("/admin/signing-keys/{kid}/retire"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// 署名鍵を削除する（`DELETE /admin/signing-keys/{kid}`）。RETIRED のみ可。
    pub async fn delete_signing_key(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        kid: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/signing-keys/{kid}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// `/{tenant_id}/admin/*`（`RequirePerms<IdpAdmin>`）への共通呼び出し。管理者の SSO Cookie と
    /// correlation_id を転送し、api のステータスを web の [`AdminApiError`] へ写す。成功時は本文を
    /// `T` へデコードする。
    async fn admin_send<T>(
        &self,
        method: Method,
        tenant_id: &str,
        path: &str,
        correlation_id: &str,
        sso: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T, AdminApiError>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut req = self.with_language(
            self.http
                .request(method, format!("{}/{}{}", self.base_url, tenant_id, path))
                .header(REQUEST_ID_HEADER, correlation_id)
                .header(
                    reqwest::header::COOKIE,
                    format!("{SSO_SESSION_COOKIE}={sso}"),
                ),
        );
        if let Some(json) = body {
            req = req.json(&json);
        }
        let response = req
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        Self::handle_admin_response(response, path).await
    }

    /// クエリ文字列を添えて GET する `admin_send` の亜種（一覧のページング。G7）。
    /// パスへ文字列連結せず reqwest に組み立てさせるのは、値のパーセントエンコードを
    /// 呼び出し側ごとに書かないため。
    async fn admin_get_with_query<T>(
        &self,
        tenant_id: &str,
        path: &str,
        correlation_id: &str,
        sso: &str,
        query: &[(&str, String)],
    ) -> Result<T, AdminApiError>
    where
        T: serde::de::DeserializeOwned,
    {
        let response = self
            .with_language(
                self.http
                    .get(format!("{}/{}{}", self.base_url, tenant_id, path))
                    .query(query)
                    .header(REQUEST_ID_HEADER, correlation_id)
                    .header(
                        reqwest::header::COOKIE,
                        format!("{SSO_SESSION_COOKIE}={sso}"),
                    ),
            )
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        Self::handle_admin_response(response, path).await
    }

    /// 本文の無い成功応答（204 等）を期待する `admin_send` の亜種。
    async fn admin_send_no_content(
        &self,
        method: Method,
        tenant_id: &str,
        path: &str,
        correlation_id: &str,
        sso: &str,
        body: Option<serde_json::Value>,
    ) -> Result<(), AdminApiError> {
        let mut req = self.with_language(
            self.http
                .request(method, format!("{}/{}{}", self.base_url, tenant_id, path))
                .header(REQUEST_ID_HEADER, correlation_id)
                .header(
                    reqwest::header::COOKIE,
                    format!("{SSO_SESSION_COOKIE}={sso}"),
                ),
        );
        if let Some(json) = body {
            req = req.json(&json);
        }
        let response = req
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let message = response
            .json::<ApiErrorBody>()
            .await
            .map(|b| b.message)
            .unwrap_or_default();
        Err(match status {
            reqwest::StatusCode::UNAUTHORIZED => AdminApiError::Unauthorized,
            reqwest::StatusCode::FORBIDDEN => AdminApiError::Forbidden,
            reqwest::StatusCode::NOT_FOUND => AdminApiError::NotFound,
            reqwest::StatusCode::BAD_REQUEST => AdminApiError::Validation(message),
            reqwest::StatusCode::CONFLICT => AdminApiError::Conflict(message),
            other => AdminApiError::Transport(format!("unexpected status {other}")),
        })
    }

    /// api の `/admin/*` 応答を `T` かエラーへ写す共通処理。
    async fn handle_admin_response<T>(
        response: reqwest::Response,
        path: &str,
    ) -> Result<T, AdminApiError>
    where
        T: serde::de::DeserializeOwned,
    {
        let status = response.status();
        if status.is_success() {
            return response
                .json::<T>()
                .await
                .map_err(|e| AdminApiError::Transport(format!("decode {path}: {e}")));
        }
        // 失敗時はエラー本文から message を取り出す（400/409 の表示用）。
        let message = response
            .json::<ApiErrorBody>()
            .await
            .map(|b| b.message)
            .unwrap_or_default();
        Err(match status {
            reqwest::StatusCode::UNAUTHORIZED => AdminApiError::Unauthorized,
            reqwest::StatusCode::FORBIDDEN => AdminApiError::Forbidden,
            reqwest::StatusCode::NOT_FOUND => AdminApiError::NotFound,
            reqwest::StatusCode::BAD_REQUEST => AdminApiError::Validation(message),
            reqwest::StatusCode::CONFLICT => AdminApiError::Conflict(message),
            other => AdminApiError::Transport(format!("unexpected status {other}")),
        })
    }

    // ── 設定画面（MT14）─────────────────────────────────────────────────────

    /// 子テナント一覧の 1 ページ分（`GET /admin/tenants`。idp.system.admin 必須。G7）。
    pub async fn list_tenants(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso_session_id: &str,
        query: &[(&str, String)],
    ) -> Result<crate::admin_dto::TenantListView, AdminApiError> {
        self.admin_get_with_query(
            tenant_id,
            "/admin/tenants",
            correlation_id,
            sso_session_id,
            query,
        )
        .await
    }

    /// 子テナント作成（`POST /admin/tenants`。idp.system.admin 必須）。作成者自身が新テナントの
    /// ブートストラップ管理者になる（ADR-0009 §4）。応答は作成したテナント。
    pub async fn create_tenant(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso_session_id: &str,
        name: &str,
    ) -> Result<crate::admin_dto::TenantCreatedView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/tenants",
            correlation_id,
            sso_session_id,
            Some(serde_json::json!({ "name": name })),
        )
        .await
    }

    /// 子テナントの表示名・状態を部分更新する（`PATCH /admin/tenants/{child_id}`。
    /// idp.system.admin 必須。MT23）。`status` は `ACTIVE` / `DISABLED`。
    pub async fn update_tenant(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso_session_id: &str,
        child_id: &str,
        name: &str,
        status: &str,
    ) -> Result<crate::admin_dto::TenantView, AdminApiError> {
        self.admin_send(
            Method::PATCH,
            tenant_id,
            &format!("/admin/tenants/{child_id}"),
            correlation_id,
            sso_session_id,
            Some(serde_json::json!({ "name": name, "status": status })),
        )
        .await
    }

    /// 子テナント削除（`DELETE /admin/tenants/{child_id}`。idp.system.admin 必須。
    /// 配下に子テナント・ユーザー・クライアントが残っていると 409）。
    pub async fn delete_tenant(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso_session_id: &str,
        child_id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/tenants/{child_id}"),
            correlation_id,
            sso_session_id,
            None,
        )
        .await
    }

    /// 子テナント管理者のパスワード再発行
    /// （`POST /admin/tenants/{child_id}/admin-password-reset`。idp.system.admin 必須）。
    /// `generated_password` を一度だけ返す。
    pub async fn reset_tenant_admin_password(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso_session_id: &str,
        child_id: &str,
        email: &str,
    ) -> Result<crate::admin_dto::UserPasswordResetView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/tenants/{child_id}/admin-password-reset"),
            correlation_id,
            sso_session_id,
            Some(serde_json::json!({ "email": email })),
        )
        .await
    }

    /// 自テナント取得（`GET /admin/settings/tenant`。idp.tenant.admin 必須）。
    pub async fn get_current_tenant(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<crate::admin_dto::TenantView, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/settings/tenant",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// 自テナント表示名の更新（`PATCH /admin/settings/tenant`。idp.tenant.admin 必須）。
    pub async fn update_current_tenant(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        name: &str,
        self_registration_enabled: bool,
    ) -> Result<crate::admin_dto::TenantView, AdminApiError> {
        self.admin_send(
            Method::PATCH,
            tenant_id,
            "/admin/settings/tenant",
            correlation_id,
            sso,
            Some(serde_json::json!({
                "name": name,
                "self_registration_enabled": self_registration_enabled,
            })),
        )
        .await
    }

    /// システム設定取得（`GET /admin/system-settings`。idp.system.admin 必須 = 実質 root のみ）。
    /// root でないと `Forbidden` が返る（web はその区画を非表示にする）。
    pub async fn get_system_settings(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<crate::admin_dto::SystemSettingsView, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/system-settings",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// システム設定更新（`PUT /admin/system-settings`。idp.system.admin 必須）。
    pub async fn update_system_settings(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        body: serde_json::Value,
    ) -> Result<crate::admin_dto::SystemSettingsView, AdminApiError> {
        self.admin_send(
            Method::PUT,
            tenant_id,
            "/admin/system-settings",
            correlation_id,
            sso,
            Some(body),
        )
        .await
    }

    /// ランタイム設定の DB 上書き更新（`PUT /admin/system-settings/runtime`。idp.system.admin 必須）。
    /// `value` が `None` または空のときは上書きを解除する。
    pub async fn update_runtime_setting(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        key: &str,
        value: Option<&str>,
    ) -> Result<crate::admin_dto::SystemSettingsView, AdminApiError> {
        self.admin_send(
            Method::PUT,
            tenant_id,
            "/admin/system-settings/runtime",
            correlation_id,
            sso,
            Some(serde_json::json!({ "key": key, "value": value })),
        )
        .await
    }

    /// api の再起動要求（`POST /{tenant_id}/admin/restart`。ADR-0017）。
    ///
    /// api は受理（202）を返してから停止するので、**この呼び出しの成功は「停止した」ではなく
    /// 「受理された」**を意味する。web 自身の停止はこの成功を確認してから行う（web が先に落ちると
    /// api への要求が届かないうえ、web が先に起動して古い共有設定を掴む）。
    pub async fn request_restart(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::POST,
            tenant_id,
            "/admin/restart",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// セルフサービスのパスワード変更（`POST /internal/account/change-password`。MT15）。
    pub async fn account_change_password(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalAccountChangePasswordRequest,
    ) -> Result<idp_contracts::auth::InternalAccountChangePasswordResponse, InternalCallError> {
        self.post_internal("/internal/account/change-password", correlation_id, req)
            .await
    }

    /// ログイン済みユーザーの表示言語を DB へ永続化する（MT20）。
    pub async fn account_update_language(
        &self,
        req: &idp_contracts::auth::InternalAccountUpdateLanguageRequest,
    ) -> Result<idp_contracts::auth::InternalAccountUpdateLanguageResponse, InternalCallError> {
        // correlation_id は不要（監査対象外）のため空文字を渡す。
        self.post_internal("/internal/account/update-language", "", req)
            .await
    }

    /// セルフサービスのプロフィール（表示名等）を取得する（設定画面のプリフィル用）。
    pub async fn account_profile(
        &self,
        req: &idp_contracts::auth::InternalAccountProfileRequest,
    ) -> Result<idp_contracts::auth::InternalAccountProfileResponse, InternalCallError> {
        self.post_internal("/internal/account/profile", "", req)
            .await
    }

    /// ログイン済みユーザーの表示名（`users.name`）を更新する。
    pub async fn account_update_name(
        &self,
        req: &idp_contracts::auth::InternalAccountUpdateNameRequest,
    ) -> Result<idp_contracts::auth::InternalAccountUpdateNameResponse, InternalCallError> {
        self.post_internal("/internal/account/update-name", "", req)
            .await
    }

    /// 有効な外部 IdP を一覧する（ログイン画面のボタン用。AP10）。
    pub async fn external_providers(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalExternalProvidersRequest,
    ) -> Result<idp_contracts::auth::InternalExternalProvidersResponse, InternalCallError> {
        self.post_internal("/internal/external/providers", correlation_id, req)
            .await
    }

    /// 外部 IdP ログインを開始し、認可エンドポイントの URL を得る（AP10）。
    pub async fn external_start(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalExternalStartRequest,
    ) -> Result<idp_contracts::auth::InternalExternalStartResponse, InternalCallError> {
        self.post_internal("/internal/external/start", correlation_id, req)
            .await
    }

    /// 外部 IdP からのコールバックを検証させる（AP10）。
    pub async fn external_callback(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalExternalCallbackRequest,
    ) -> Result<idp_contracts::auth::InternalExternalCallbackResponse, InternalCallError> {
        self.post_internal("/internal/external/callback", correlation_id, req)
            .await
    }

    /// 外部 SAML IdP のアサーションを api へ渡して検証させる（AP12）。
    pub async fn external_saml_acs(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalExternalSamlAcsRequest,
    ) -> Result<idp_contracts::auth::InternalExternalCallbackResponse, InternalCallError> {
        self.post_internal("/internal/external/saml/acs", correlation_id, req)
            .await
    }

    /// 登録済み認証器の一覧とリカバリーコードの残数を取得する（AP9）。
    pub async fn account_authenticators(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalAuthenticatorsRequest,
    ) -> Result<idp_contracts::auth::InternalAuthenticatorsResponse, InternalCallError> {
        self.post_internal("/internal/account/authenticators", correlation_id, req)
            .await
    }

    /// 認証器の状態を変える（一時停止・再開・失効。AP9）。
    pub async fn account_authenticator_status(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalAuthenticatorStatusRequest,
    ) -> Result<idp_contracts::auth::InternalAuthenticatorStatusResponse, InternalCallError> {
        self.post_internal(
            "/internal/account/authenticators/status",
            correlation_id,
            req,
        )
        .await
    }

    /// リカバリーコードを（再）発行する（AP9）。平文はこの応答でのみ得られる。
    pub async fn account_recovery_codes(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalRecoveryCodesRequest,
    ) -> Result<idp_contracts::auth::InternalRecoveryCodesResponse, InternalCallError> {
        self.post_internal("/internal/account/recovery-codes", correlation_id, req)
            .await
    }

    /// MFA 待ちの利用者へ email OTP を送る（AP9）。
    pub async fn account_email_otp(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalEmailOtpRequest,
    ) -> Result<idp_contracts::auth::InternalEmailOtpResponse, InternalCallError> {
        self.post_internal("/internal/account/email-otp", correlation_id, req)
            .await
    }

    /// MFA 待ちの利用者へ SMS OTP を送る（AP13）。
    pub async fn account_sms_otp(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalSmsOtpRequest,
    ) -> Result<idp_contracts::auth::InternalSmsOtpResponse, InternalCallError> {
        self.post_internal("/internal/account/sms-otp", correlation_id, req)
            .await
    }

    /// 電話番号の登録開始（確認コードの送信。AP13）。
    pub async fn account_phone_register(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalPhoneRegistrationRequest,
    ) -> Result<idp_contracts::auth::InternalPhoneRegistrationResponse, InternalCallError> {
        self.post_internal("/internal/account/phone/register", correlation_id, req)
            .await
    }

    /// 電話番号の登録確認（AP13）。
    pub async fn account_phone_confirm(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalPhoneConfirmationRequest,
    ) -> Result<idp_contracts::auth::InternalPhoneConfirmationResponse, InternalCallError> {
        self.post_internal("/internal/account/phone/confirm", correlation_id, req)
            .await
    }

    /// 重要操作の直前に step-up が要るかを判定する（AP5）。
    pub async fn step_up_check(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalStepUpCheckRequest,
    ) -> Result<idp_contracts::auth::InternalStepUpCheckResponse, InternalCallError> {
        self.post_internal("/internal/step-up/check", correlation_id, req)
            .await
    }

    /// step-up の本人確認を検証する（AP5）。
    pub async fn step_up_verify(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalStepUpVerifyRequest,
    ) -> Result<idp_contracts::auth::InternalStepUpVerifyResponse, InternalCallError> {
        self.post_internal("/internal/step-up/verify", correlation_id, req)
            .await
    }

    /// セルフサービスのセキュリティ画面の表示内容（セッション一覧・連携済みアプリ）を取得する（G10）。
    pub async fn account_security(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalAccountSecurityRequest,
    ) -> Result<idp_contracts::auth::InternalAccountSecurityResponse, InternalCallError> {
        self.post_internal("/internal/account/security", correlation_id, req)
            .await
    }

    /// ログイン中セッションを失効させる（G10）。
    pub async fn account_revoke_session(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalAccountRevokeSessionRequest,
    ) -> Result<idp_contracts::auth::InternalAccountRevokeSessionResponse, InternalCallError> {
        self.post_internal(
            "/internal/account/security/revoke-session",
            correlation_id,
            req,
        )
        .await
    }

    /// 連携済みアプリの同意を取り消す（G10）。
    pub async fn account_revoke_consent(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalAccountRevokeConsentRequest,
    ) -> Result<idp_contracts::auth::InternalAccountRevokeConsentResponse, InternalCallError> {
        self.post_internal(
            "/internal/account/security/revoke-consent",
            correlation_id,
            req,
        )
        .await
    }

    /// ログイン中ユーザーの所属テナント（`ACTIVE`）を列挙する（テナント切り替え UI 用）。
    pub async fn account_tenants(
        &self,
        req: &idp_contracts::auth::InternalAccountTenantsRequest,
    ) -> Result<idp_contracts::auth::InternalAccountTenantsResponse, InternalCallError> {
        self.post_internal("/internal/account/tenants", "", req)
            .await
    }

    /// api と共有するランタイム設定の DB 上書き値を取得する（MT26 / ADR-0013）。
    ///
    /// web は DB を持たないため、`COOKIE_SECURE`・`HSTS_MAX_AGE`・`AUTH_SESSION_TTL_SECS` のような
    /// 「api と値がずれると壊れる」設定の DB 上書き値を api から受け取る。起動時に 1 度だけ呼ぶ
    /// （反映には web の再起動が必要。MT27）。
    ///
    /// 返るのは DB 上書き値だけで、api の有効値ではない。ここに無いキーは web 自身の
    /// ENV → 既定値で解決する。
    pub async fn fetch_shared_runtime_settings(&self) -> anyhow::Result<HashMap<String, String>> {
        let path = SHARED_RUNTIME_SETTINGS_PATH;
        let response = self
            .http
            .get(format!("{}{}", self.base_url, path))
            .header(SERVICE_TOKEN_HEADER, &self.service_token)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("request to api {path} failed: {e}"))?;
        let status = response.status();
        if !status.is_success() {
            // 401 はサービストークンの不一致（api と web で `INTERNAL_SERVICE_TOKEN` がずれている）。
            anyhow::bail!("api {path} returned unexpected status {status}");
        }
        let body = response
            .json::<SharedRuntimeSettingsResponse>()
            .await
            .map_err(|e| anyhow::anyhow!("failed to decode api {path} response: {e}"))?;
        Ok(body.settings.into_iter().collect())
    }

    /// api への到達性を確認する（`GET /healthz`）。web の readiness で使う。
    pub async fn is_api_reachable(&self) -> bool {
        match self
            .http
            .get(format!("{}/healthz", self.base_url))
            .send()
            .await
        {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// api の `GET /version/schema` から DB スキーマ（マイグレーション）の適用状態を取得する。
    /// バージョン情報画面の表示用。api 未到達・デコード失敗はいずれも `None`（fail-soft。画面は
    /// 「取得できません」を表示する）。認証不要の公開エンドポイントのためサービストークンは付けない。
    pub async fn fetch_schema_version(&self) -> Option<SchemaVersionInfo> {
        self.http
            .get(format!("{}/version/schema", self.base_url))
            .send()
            .await
            .ok()?
            .json::<SchemaVersionInfo>()
            .await
            .ok()
    }

    /// `/internal/*` への POST 共通処理（サービストークン＋correlation_id を付与して JSON をやり取り）。
    async fn post_internal<B, R>(
        &self,
        path: &str,
        correlation_id: &str,
        body: &B,
    ) -> Result<R, InternalCallError>
    where
        B: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let response = self
            .with_language(
                self.http
                    .post(format!("{}{}", self.base_url, path))
                    .header(SERVICE_TOKEN_HEADER, &self.service_token)
                    .header(REQUEST_ID_HEADER, correlation_id),
            )
            .json(body)
            .send()
            .await
            .map_err(|e| InternalCallError::failed(format!("request to api {path} failed: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            // テナントを解決できなかった 400 だけは呼び出し側で 404 の画面へ倒せるよう区別する
            // （MT28）。本文を読むのはこの分岐のためだけなので、失敗しても素の失敗へ倒す。
            if status == reqwest::StatusCode::BAD_REQUEST
                && is_unknown_tenant_error(&response.text().await.unwrap_or_default())
            {
                return Err(InternalCallError::UnknownTenant);
            }
            // 内部認証の業務結果（invalid/locked 等）は 200＋result で返る。ここに来るのは
            // トークン不一致（401）やサーバ障害など、web の実装/構成エラー。
            return Err(InternalCallError::failed(format!(
                "api {path} returned unexpected status {status}"
            )));
        }
        response.json::<R>().await.map_err(|e| {
            InternalCallError::failed(format!("failed to decode api {path} response: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{admin_display_label, admin_identity, admin_session_for_status, AdminSession};
    use idp_contracts::admin::WhoamiResponse;

    /// api の「テナントを解決できない」400 だけを見分ける（MT28）。判別はコードで行い、人間向けの
    /// 説明文には依存しない。
    #[test]
    fn only_the_unknown_tenant_code_is_recognized() {
        assert!(super::is_unknown_tenant_error(
            r#"{"error":"unknown_tenant","error_description":"unknown or disabled tenant"}"#
        ));
        // 他の 400（本文の不正など）は「その他の失敗」＝ 502 のまま。
        assert!(!super::is_unknown_tenant_error(
            r#"{"error":"invalid_request","error_description":"missing or invalid tenant_id"}"#
        ));
        // 説明文だけが一致しても引っかからない（文言を直しても壊れない／壊さない）。
        assert!(!super::is_unknown_tenant_error(
            r#"{"error":"invalid_request","error_description":"unknown or disabled tenant"}"#
        ));
        // 本文が読めないときは fail-safe（誤って 404 の画面を出さない）。
        for body in ["", "not json", "[]", "{}", r#"{"error":123}"#] {
            assert!(!super::is_unknown_tenant_error(body), "{body:?}");
        }
    }

    /// 失敗の種類が画面のステータスへ写ること（MT28）。
    #[test]
    fn internal_call_failures_map_to_the_intended_status() {
        use crate::handlers::internal_call_status;
        assert_eq!(
            internal_call_status(&super::InternalCallError::UnknownTenant),
            axum::http::StatusCode::NOT_FOUND
        );
        assert_eq!(
            internal_call_status(&super::InternalCallError::Failed("boom".to_string())),
            axum::http::StatusCode::BAD_GATEWAY
        );
    }

    /// whoami の非 200 応答の写像。404（api がテナントを解決できない）を `Error` に含めない
    /// ＝ 画面を 502 に倒さないことの回帰テスト。
    #[test]
    fn whoami_statuses_map_to_sessions() {
        assert!(matches!(
            admin_session_for_status(reqwest::StatusCode::UNAUTHORIZED),
            AdminSession::Unauthenticated
        ));
        assert!(matches!(
            admin_session_for_status(reqwest::StatusCode::FORBIDDEN),
            AdminSession::Forbidden
        ));
        assert!(matches!(
            admin_session_for_status(reqwest::StatusCode::NOT_FOUND),
            AdminSession::NotFound
        ));
        // テナント解決の一時障害（503）等、想定外はゲートウェイ障害として扱う。
        assert!(matches!(
            admin_session_for_status(reqwest::StatusCode::SERVICE_UNAVAILABLE),
            AdminSession::Error
        ));
        assert!(matches!(
            admin_session_for_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
            AdminSession::Error
        ));
    }

    fn whoami(name: Option<&str>, preferred_username: Option<&str>) -> WhoamiResponse {
        WhoamiResponse {
            user_id: "019f8ea9-0879-7f75-85ab-68b0571b6e7d".to_string(),
            name: name.map(str::to_string),
            preferred_username: preferred_username.map(str::to_string),
            tenant_name: Some("Acme".to_string()),
        }
    }

    #[test]
    fn display_label_prefers_name_then_username_then_id() {
        // 表示名があれば表示名。
        assert_eq!(
            admin_display_label(whoami(Some("Alice"), Some("alice"))),
            "Alice"
        );
        // 表示名が無ければログイン識別子。
        assert_eq!(admin_display_label(whoami(None, Some("alice"))), "alice");
        // どちらも無ければ内部 ID。
        assert_eq!(
            admin_display_label(whoami(None, None)),
            "019f8ea9-0879-7f75-85ab-68b0571b6e7d"
        );
    }

    /// ヘッダのテナント名は api の whoami 由来。返らない・空白のみのときは表示を省く
    /// （旧 api との混在デプロイでもヘッダ以外は壊れない）。
    #[test]
    fn identity_carries_tenant_name_when_present() {
        let mut w = whoami(Some("Alice"), Some("alice"));
        assert_eq!(
            admin_identity(w.clone()).tenant_name.as_deref(),
            Some("Acme")
        );

        w.tenant_name = None;
        assert_eq!(admin_identity(w.clone()).tenant_name, None);

        w.tenant_name = Some("   ".to_string());
        assert_eq!(admin_identity(w).tenant_name, None);
    }

    #[test]
    fn display_label_treats_blank_values_as_absent() {
        // 空白のみは未設定として扱い、次の候補へフォールバックする。
        assert_eq!(
            admin_display_label(whoami(Some("   "), Some("alice"))),
            "alice"
        );
        assert_eq!(
            admin_display_label(whoami(Some(""), Some(""))),
            "019f8ea9-0879-7f75-85ab-68b0571b6e7d"
        );
    }
}
