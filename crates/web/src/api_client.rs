//! api への HTTP クライアント（ADR-0007）。
//!
//! web は DB を持たず、データ取得/操作はすべて api の HTTP エンドポイント越しに行う。本モジュールは
//! その唯一の出入口。内部認証（`/internal/authenticate*`）はサービス認証トークン（`X-Internal-Auth-Token`）
//! を付与して呼ぶ。DTO は `idp-contracts` で api と共有し、コンパイル時に契約整合を保証する。
//!
//! `/admin/*`（JSON 管理 API）はテナント経路（`/{tenant_id}/admin/*`。ADR-0009 §6）で呼ぶ。
//! テナント id は web の経路（`crate::tenant::WebTenant`）から呼び出し側が明示的に渡す（MT13）。

use crate::admin_dto::{
    ApiErrorBody, AuditLogView, ClientCreatedView, ClientSecretView, ClientView,
    InvitationCreatedView, MemberView, UserCreatedView,
};
use idp_contracts::admin::{
    AvailablePermissionsResponse, ClientStatusResponse, SamlServiceProviderRegisterRequest,
    SamlServiceProviderResponse, SamlServiceProviderUpdateRequest, SamlSpMetadataImportResponse,
    UserPermissionsResponse, UserSummaryResponse, WhoamiResponse,
};
use idp_contracts::auth::{
    InternalAdminAuthenticateRequest, InternalAdminAuthenticateResponse,
    InternalAdminChangePasswordRequest, InternalAdminChangePasswordResponse,
    InternalAuthenticateRequest, InternalAuthenticateResponse, InternalChangePasswordRequest,
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
    InternalTotpConfirmRequest, InternalTotpConfirmResponse, InternalTotpDeleteRequest,
    InternalTotpDeleteResponse, InternalTotpSetupRequest, InternalTotpSetupResponse,
    InternalVerifyTotpRequest, InternalVerifyTotpResponse,
};
use reqwest::Method;

/// サービス認証トークンのヘッダ名（api 側 `require_service_token` と一致させる）。
const SERVICE_TOKEN_HEADER: &str = "x-internal-auth-token";
/// correlation_id（requestId）の伝播ヘッダ名（api 側 correlation ミドルウェアと一致させる）。
const REQUEST_ID_HEADER: &str = "x-request-id";
/// SSO セッション Cookie 名（api の `cookies::SSO_SESSION_COOKIE` と一致させる）。
const SSO_SESSION_COOKIE: &str = "sso_session_id";

/// メール検証リンク消費（SEC6b）の結果。
pub enum VerifyEmailResult {
    /// `email_verified` を立てた。
    Verified,
    /// トークンが無効・期限切れ・使用済み・別テナント。
    InvalidOrExpired,
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

/// 管理者の SSO Cookie を api の `/admin/*`（`RequirePerms<IdpAdmin>`）へ転送した結果（ADR-0007 §4）。
pub enum AdminSession {
    /// 有効な SSO ＋ テナント admin 権限（`idp.tenant.admin`／`idp.system.admin`）保有。管理利用者の内部 ID を返す。
    Authenticated(String),
    /// 未認証・SSO 期限切れ（ログイン画面へ誘導する）。
    Unauthenticated,
    /// 認証済みだがテナント admin 権限なし（403 画面）。
    Forbidden,
    /// api 呼び出し失敗（構成/障害）。
    Error,
}

/// api への HTTP クライアント。`reqwest::Client` は接続プールを内包するため clone は安価。
#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    base_url: String,
    service_token: String,
}

impl ApiClient {
    pub fn new(base_url: impl Into<String>, service_token: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into(),
            service_token: service_token.into(),
        }
    }

    /// OIDC ログイン認証（`POST /internal/authenticate`）。
    pub async fn authenticate(
        &self,
        correlation_id: &str,
        req: &InternalAuthenticateRequest,
    ) -> anyhow::Result<InternalAuthenticateResponse> {
        self.post_internal("/internal/authenticate", correlation_id, req)
            .await
    }

    /// 強制パスワード変更（`POST /internal/change-password`、ADR-0009 §5）。
    pub async fn change_password(
        &self,
        correlation_id: &str,
        req: &InternalChangePasswordRequest,
    ) -> anyhow::Result<InternalChangePasswordResponse> {
        self.post_internal("/internal/change-password", correlation_id, req)
            .await
    }

    /// 管理コンソール認証（`POST /internal/authenticate/admin`）。
    pub async fn authenticate_admin(
        &self,
        correlation_id: &str,
        req: &InternalAdminAuthenticateRequest,
    ) -> anyhow::Result<InternalAdminAuthenticateResponse> {
        self.post_internal("/internal/authenticate/admin", correlation_id, req)
            .await
    }

    /// エンドユーザー・ポータル認証（`POST /internal/authenticate/portal`）。
    pub async fn authenticate_portal(
        &self,
        correlation_id: &str,
        req: &InternalPortalAuthenticateRequest,
    ) -> anyhow::Result<InternalPortalAuthenticateResponse> {
        self.post_internal("/internal/authenticate/portal", correlation_id, req)
            .await
    }

    /// ポータルの TOTP 検証（`POST /internal/authenticate/portal/mfa`）。
    pub async fn authenticate_portal_mfa(
        &self,
        correlation_id: &str,
        req: &InternalPortalMfaRequest,
    ) -> anyhow::Result<InternalPortalMfaResponse> {
        self.post_internal("/internal/authenticate/portal/mfa", correlation_id, req)
            .await
    }

    /// ポータルの強制パスワード変更（`POST /internal/authenticate/portal/change-password`、ADR-0009 §5）。
    pub async fn authenticate_portal_change_password(
        &self,
        correlation_id: &str,
        req: &InternalPortalChangePasswordRequest,
    ) -> anyhow::Result<InternalPortalChangePasswordResponse> {
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
    ) -> anyhow::Result<InternalAdminChangePasswordResponse> {
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
    ) -> anyhow::Result<InternalPasswordResetRequestResponse> {
        self.post_internal("/internal/password-reset/request", correlation_id, req)
            .await
    }

    /// パスワードリセット実行（`POST /internal/password-reset/complete`。MT18）。
    pub async fn password_reset_complete(
        &self,
        correlation_id: &str,
        req: &InternalPasswordResetCompleteRequest,
    ) -> anyhow::Result<InternalPasswordResetCompleteResponse> {
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
    ) -> anyhow::Result<InternalConsentInfoResponse> {
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
            .map_err(|e| anyhow::anyhow!("request to api /internal/consent-info failed: {e}"))?;
        response
            .json::<InternalConsentInfoResponse>()
            .await
            .map_err(|e| anyhow::anyhow!("failed to decode consent-info response: {e}"))
    }

    /// 同意承認（`POST /internal/consent/approve`）。
    pub async fn consent_approve(
        &self,
        correlation_id: &str,
        req: &InternalConsentApproveRequest,
    ) -> anyhow::Result<InternalConsentApproveResponse> {
        self.post_internal("/internal/consent/approve", correlation_id, req)
            .await
    }

    /// 同意拒否（`POST /internal/consent/deny`）。
    pub async fn consent_deny(
        &self,
        correlation_id: &str,
        req: &InternalConsentDenyRequest,
    ) -> anyhow::Result<InternalConsentDenyResponse> {
        self.post_internal("/internal/consent/deny", correlation_id, req)
            .await
    }

    /// TOTP セットアップ開始（`POST /internal/mfa/totp/setup`）。QR URI と生シークレットを返す。
    pub async fn totp_setup(
        &self,
        correlation_id: &str,
        req: &InternalTotpSetupRequest,
    ) -> anyhow::Result<InternalTotpSetupResponse> {
        self.post_internal("/internal/mfa/totp/setup", correlation_id, req)
            .await
    }

    /// TOTP 確認（`POST /internal/mfa/totp/confirm`）。6 桁コードで有効化する。
    pub async fn totp_confirm(
        &self,
        correlation_id: &str,
        req: &InternalTotpConfirmRequest,
    ) -> anyhow::Result<InternalTotpConfirmResponse> {
        self.post_internal("/internal/mfa/totp/confirm", correlation_id, req)
            .await
    }

    /// TOTP 削除（`POST /internal/mfa/totp/delete`）。MFA を無効化する。
    pub async fn totp_delete(
        &self,
        correlation_id: &str,
        req: &InternalTotpDeleteRequest,
    ) -> anyhow::Result<InternalTotpDeleteResponse> {
        self.post_internal("/internal/mfa/totp/delete", correlation_id, req)
            .await
    }

    /// ログインフロー TOTP 検証（`POST /internal/mfa/totp/verify`）。
    pub async fn verify_totp(
        &self,
        correlation_id: &str,
        req: &InternalVerifyTotpRequest,
    ) -> anyhow::Result<InternalVerifyTotpResponse> {
        self.post_internal("/internal/mfa/totp/verify", correlation_id, req)
            .await
    }

    // ─── Passkey（WebAuthn）API ───────────────────────────────────────────

    /// Passkey 登録開始（`POST /internal/passkey/register/begin`）。
    pub async fn passkey_register_begin(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyRegisterBeginRequest,
    ) -> anyhow::Result<InternalPasskeyRegisterBeginResponse> {
        self.post_internal("/internal/passkey/register/begin", correlation_id, req)
            .await
    }

    /// Passkey 登録完了（`POST /internal/passkey/register/complete`）。
    pub async fn passkey_register_complete(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyRegisterCompleteRequest,
    ) -> anyhow::Result<InternalPasskeyRegisterCompleteResponse> {
        self.post_internal("/internal/passkey/register/complete", correlation_id, req)
            .await
    }

    /// Passkey 削除（`POST /internal/passkey/delete`）。
    pub async fn passkey_delete(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyDeleteRequest,
    ) -> anyhow::Result<InternalPasskeyDeleteResponse> {
        self.post_internal("/internal/passkey/delete", correlation_id, req)
            .await
    }

    /// 登録済み Passkey 一覧（`POST /internal/passkey/list`）。
    pub async fn passkey_list(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyListRequest,
    ) -> anyhow::Result<InternalPasskeyListResponse> {
        self.post_internal("/internal/passkey/list", correlation_id, req)
            .await
    }

    /// Passkey 認証開始（`POST /internal/passkey/login/begin`）。
    pub async fn passkey_login_begin(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyLoginBeginRequest,
    ) -> anyhow::Result<InternalPasskeyLoginBeginResponse> {
        self.post_internal("/internal/passkey/login/begin", correlation_id, req)
            .await
    }

    /// Passkey 認証完了（`POST /internal/passkey/login/complete`）。
    pub async fn passkey_login_complete(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyLoginCompleteRequest,
    ) -> anyhow::Result<InternalPasskeyLoginCompleteResponse> {
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
                Ok(w) => AdminSession::Authenticated(w.user_id),
                Err(e) => {
                    tracing::error!(error = %e, "failed to decode whoami response");
                    AdminSession::Error
                }
            },
            reqwest::StatusCode::UNAUTHORIZED => AdminSession::Unauthenticated,
            reqwest::StatusCode::FORBIDDEN => AdminSession::Forbidden,
            other => {
                tracing::error!(status = %other, "unexpected whoami status from api");
                AdminSession::Error
            }
        }
    }

    // ── 管理コンソール → JSON 管理 API（`/{tenant_id}/admin/*`、SSO Cookie 転送）───────────────

    /// クライアント一覧（`GET /admin/clients`）。
    pub async fn list_clients(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<Vec<ClientView>, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/clients",
            correlation_id,
            sso,
            None,
        )
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

    /// 利用者検索（`GET /admin/users?q=`）。該当なしは `NotFound`。
    pub async fn search_user(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        q: &str,
    ) -> Result<UserSummaryResponse, AdminApiError> {
        let response = self
            .http
            .get(format!("{}/{}/admin/users", self.base_url, tenant_id))
            .query(&[("q", q)])
            .header(REQUEST_ID_HEADER, correlation_id)
            .header(
                reqwest::header::COOKIE,
                format!("{SSO_SESSION_COOKIE}={sso}"),
            )
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        Self::handle_admin_response(response, "/admin/users").await
    }

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

    // ── メンバー・招待（ADR-0009 §3）─────────────────────────────────────────

    /// メンバー一覧（`GET /admin/members`。HOME / GUEST を問わない）。
    pub async fn list_members(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<Vec<MemberView>, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/members",
            correlation_id,
            sso,
            None,
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
            .http
            .get(format!("{}/{}/admin/audit-logs", self.base_url, tenant_id))
            .query(query)
            .header(REQUEST_ID_HEADER, correlation_id)
            .header(
                reqwest::header::COOKIE,
                format!("{SSO_SESSION_COOKIE}={sso}"),
            )
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        Self::handle_admin_response(response, "/admin/audit-logs").await
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
        let mut req = self
            .http
            .request(method, format!("{}/{}{}", self.base_url, tenant_id, path))
            .header(REQUEST_ID_HEADER, correlation_id)
            .header(
                reqwest::header::COOKIE,
                format!("{SSO_SESSION_COOKIE}={sso}"),
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
        let mut req = self
            .http
            .request(method, format!("{}/{}{}", self.base_url, tenant_id, path))
            .header(REQUEST_ID_HEADER, correlation_id)
            .header(
                reqwest::header::COOKIE,
                format!("{SSO_SESSION_COOKIE}={sso}"),
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

    /// 子テナント一覧（`GET /admin/tenants`。idp.system.admin 必須）。
    pub async fn list_tenants(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso_session_id: &str,
    ) -> Result<Vec<crate::admin_dto::TenantView>, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/tenants",
            correlation_id,
            sso_session_id,
            None,
        )
        .await
    }

    /// 子テナント作成（`POST /admin/tenants`。idp.system.admin 必須）。
    pub async fn create_tenant(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso_session_id: &str,
        name: &str,
        admin_email: &str,
    ) -> Result<crate::admin_dto::TenantCreatedView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/tenants",
            correlation_id,
            sso_session_id,
            Some(serde_json::json!({ "name": name, "admin_email": admin_email })),
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

    /// セルフサービスのパスワード変更（`POST /internal/account/change-password`。MT15）。
    pub async fn account_change_password(
        &self,
        correlation_id: &str,
        req: &idp_contracts::auth::InternalAccountChangePasswordRequest,
    ) -> anyhow::Result<idp_contracts::auth::InternalAccountChangePasswordResponse> {
        self.post_internal("/internal/account/change-password", correlation_id, req)
            .await
    }

    /// ログイン済みユーザーの表示言語を DB へ永続化する（MT20）。
    pub async fn account_update_language(
        &self,
        req: &idp_contracts::auth::InternalAccountUpdateLanguageRequest,
    ) -> anyhow::Result<idp_contracts::auth::InternalAccountUpdateLanguageResponse> {
        // correlation_id は不要（監査対象外）のため空文字を渡す。
        self.post_internal("/internal/account/update-language", "", req)
            .await
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

    /// `/internal/*` への POST 共通処理（サービストークン＋correlation_id を付与して JSON をやり取り）。
    async fn post_internal<B, R>(
        &self,
        path: &str,
        correlation_id: &str,
        body: &B,
    ) -> anyhow::Result<R>
    where
        B: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let response = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .header(SERVICE_TOKEN_HEADER, &self.service_token)
            .header(REQUEST_ID_HEADER, correlation_id)
            .json(body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("request to api {path} failed: {e}"))?;

        let status = response.status();
        if !status.is_success() {
            // 内部認証の業務結果（invalid/locked 等）は 200＋result で返る。ここに来るのは
            // トークン不一致（401）やサーバ障害など、web の実装/構成エラー。
            anyhow::bail!("api {path} returned unexpected status {status}");
        }
        response
            .json::<R>()
            .await
            .map_err(|e| anyhow::anyhow!("failed to decode api {path} response: {e}"))
    }
}
