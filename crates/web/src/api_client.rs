//! api への HTTP クライアント（ADR-0007）。
//!
//! web は DB を持たず、データ取得/操作はすべて api の HTTP エンドポイント越しに行う。本モジュールは
//! その唯一の出入口。内部認証（`/internal/authenticate*`）はサービス認証トークン（`X-Internal-Auth-Token`）
//! を付与して呼ぶ。DTO は `idp-contracts` で api と共有し、コンパイル時に契約整合を保証する。

use crate::admin_dto::{
    ApiErrorBody, AuditLogView, ClientCreatedView, ClientSecretView, ClientView,
};
use idp_contracts::admin::{
    AvailablePermissionsResponse, ClientStatusResponse, UserPermissionsResponse,
    UserSummaryResponse, WhoamiResponse,
};
use idp_contracts::auth::{
    InternalAdminAuthenticateRequest, InternalAdminAuthenticateResponse,
    InternalAuthenticateRequest, InternalAuthenticateResponse, InternalLogoutRequest,
};
use reqwest::Method;

/// サービス認証トークンのヘッダ名（api 側 `require_service_token` と一致させる）。
const SERVICE_TOKEN_HEADER: &str = "x-internal-auth-token";
/// correlation_id（requestId）の伝播ヘッダ名（api 側 correlation ミドルウェアと一致させる）。
const REQUEST_ID_HEADER: &str = "x-request-id";
/// SSO セッション Cookie 名（api の `cookies::SSO_SESSION_COOKIE` と一致させる）。
const SSO_SESSION_COOKIE: &str = "sso_session_id";

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
    /// 有効な SSO ＋ `idp.admin` 保有。管理利用者の内部 ID を返す。
    Authenticated(String),
    /// 未認証・SSO 期限切れ（ログイン画面へ誘導する）。
    Unauthenticated,
    /// 認証済みだが `idp.admin` 権限なし（403 画面）。
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

    /// 管理コンソール認証（`POST /internal/authenticate/admin`）。
    pub async fn authenticate_admin(
        &self,
        correlation_id: &str,
        req: &InternalAdminAuthenticateRequest,
    ) -> anyhow::Result<InternalAdminAuthenticateResponse> {
        self.post_internal("/internal/authenticate/admin", correlation_id, req)
            .await
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

    /// 管理者の SSO Cookie を api の `GET /admin/whoami` へ転送し、認証状態と身元を得る（ADR-0007 §4）。
    pub async fn admin_whoami(&self, correlation_id: &str, sso_session_id: &str) -> AdminSession {
        let response = match self
            .http
            .get(format!("{}/admin/whoami", self.base_url))
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

    // ── 管理コンソール → JSON 管理 API（`/admin/*`、SSO Cookie 転送）───────────────

    /// クライアント一覧（`GET /admin/clients`）。
    pub async fn list_clients(
        &self,
        correlation_id: &str,
        sso: &str,
    ) -> Result<Vec<ClientView>, AdminApiError> {
        self.admin_send(Method::GET, "/admin/clients", correlation_id, sso, None)
            .await
    }

    /// 単一クライアント（`GET /admin/clients/{id}`）。
    pub async fn get_client(
        &self,
        correlation_id: &str,
        sso: &str,
        client_id: &str,
    ) -> Result<ClientView, AdminApiError> {
        self.admin_send(
            Method::GET,
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
        sso: &str,
        body: serde_json::Value,
    ) -> Result<ClientCreatedView, AdminApiError> {
        self.admin_send(
            Method::POST,
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
        sso: &str,
        client_id: &str,
        body: serde_json::Value,
    ) -> Result<ClientView, AdminApiError> {
        self.admin_send(
            Method::PATCH,
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
        sso: &str,
        client_id: &str,
    ) -> Result<ClientSecretView, AdminApiError> {
        self.admin_send(
            Method::POST,
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
        sso: &str,
        q: &str,
    ) -> Result<UserSummaryResponse, AdminApiError> {
        let req = self
            .http
            .get(format!("{}/admin/users", self.base_url))
            .query(&[("q", q)])
            .header(REQUEST_ID_HEADER, correlation_id)
            .header(
                reqwest::header::COOKIE,
                format!("{SSO_SESSION_COOKIE}={sso}"),
            );
        let response = req
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        Self::handle_admin_response(response, "/admin/users").await
    }

    /// 利用者取得（`GET /admin/users/{id}`）。
    pub async fn get_user(
        &self,
        correlation_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<UserSummaryResponse, AdminApiError> {
        self.admin_send(
            Method::GET,
            &format!("/admin/users/{user_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// 付与可能な権限コード（`GET /admin/permissions`）。
    pub async fn available_permissions(
        &self,
        correlation_id: &str,
        sso: &str,
    ) -> Result<AvailablePermissionsResponse, AdminApiError> {
        self.admin_send(Method::GET, "/admin/permissions", correlation_id, sso, None)
            .await
    }

    /// 保有権限一覧（`GET /admin/users/{id}/permissions`）。
    pub async fn list_user_permissions(
        &self,
        correlation_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<UserPermissionsResponse, AdminApiError> {
        self.admin_send(
            Method::GET,
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
        sso: &str,
        user_id: &str,
        code: &str,
    ) -> Result<UserPermissionsResponse, AdminApiError> {
        self.admin_send(
            Method::POST,
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
        sso: &str,
        user_id: &str,
        code: &str,
    ) -> Result<UserPermissionsResponse, AdminApiError> {
        self.admin_send(
            Method::DELETE,
            &format!("/admin/users/{user_id}/permissions/{code}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    // ── 状況確認（監査ログ・クライアント状況）─────────────────────────────────

    /// 監査ログ検索（`GET /admin/audit-logs`）。フィルタは `(key, value)` の並びで渡す。
    pub async fn search_audit_logs(
        &self,
        correlation_id: &str,
        sso: &str,
        query: &[(&str, String)],
    ) -> Result<Vec<AuditLogView>, AdminApiError> {
        let req = self
            .http
            .get(format!("{}/admin/audit-logs", self.base_url))
            .query(query)
            .header(REQUEST_ID_HEADER, correlation_id)
            .header(
                reqwest::header::COOKIE,
                format!("{SSO_SESSION_COOKIE}={sso}"),
            );
        let response = req
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        Self::handle_admin_response(response, "/admin/audit-logs").await
    }

    /// クライアント状況一覧（`GET /admin/clients/status`）。
    pub async fn list_client_status(
        &self,
        correlation_id: &str,
        sso: &str,
    ) -> Result<Vec<ClientStatusResponse>, AdminApiError> {
        self.admin_send(
            Method::GET,
            "/admin/clients/status",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    // ── 署名鍵管理（K1）─────────────────────────────────────────────────────

    /// 署名鍵一覧（`GET /admin/signing-keys`）。
    pub async fn list_signing_keys(
        &self,
        correlation_id: &str,
        sso: &str,
    ) -> Result<Vec<crate::admin_dto::SigningKeyView>, AdminApiError> {
        self.admin_send(Method::GET, "/admin/signing-keys", correlation_id, sso, None)
            .await
    }

    /// 新規署名鍵を生成する（`POST /admin/signing-keys`）。`algorithm` は `RS256` または `ES256`。
    pub async fn generate_signing_key(
        &self,
        correlation_id: &str,
        sso: &str,
        algorithm: &str,
    ) -> Result<crate::admin_dto::SigningKeyView, AdminApiError> {
        self.admin_send(
            Method::POST,
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
        sso: &str,
        kid: &str,
    ) -> Result<(), AdminApiError> {
        let response = self
            .http
            .post(format!("{}/admin/signing-keys/{kid}/retire", self.base_url))
            .header(REQUEST_ID_HEADER, correlation_id)
            .header(
                reqwest::header::COOKIE,
                format!("{SSO_SESSION_COOKIE}={sso}"),
            )
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
            other => AdminApiError::Transport(format!("unexpected status {other}")),
        })
    }

    /// 署名鍵を削除する（`DELETE /admin/signing-keys/{kid}`）。RETIRED のみ可。
    pub async fn delete_signing_key(
        &self,
        correlation_id: &str,
        sso: &str,
        kid: &str,
    ) -> Result<(), AdminApiError> {
        let response = self
            .http
            .delete(format!("{}/admin/signing-keys/{kid}", self.base_url))
            .header(REQUEST_ID_HEADER, correlation_id)
            .header(
                reqwest::header::COOKIE,
                format!("{SSO_SESSION_COOKIE}={sso}"),
            )
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
            other => AdminApiError::Transport(format!("unexpected status {other}")),
        })
    }

    /// `/admin/*`（`RequirePerms<IdpAdmin>`）への共通呼び出し。管理者の SSO Cookie と correlation_id を
    /// 転送し、api のステータスを web の [`AdminApiError`] へ写す。成功時は本文を `T` へデコードする。
    async fn admin_send<T>(
        &self,
        method: Method,
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
            .request(method, format!("{}{}", self.base_url, path))
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
