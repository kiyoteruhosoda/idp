//! api への HTTP クライアント（ADR-0007）。
//!
//! web は DB を持たず、データ取得/操作はすべて api の HTTP エンドポイント越しに行う。本モジュールは
//! その唯一の出入口。内部認証（`/internal/authenticate*`）はサービス認証トークン（`X-Internal-Auth-Token`）
//! を付与して呼ぶ。DTO は `idp-contracts` で api と共有し、コンパイル時に契約整合を保証する。

use idp_contracts::auth::{
    InternalAdminAuthenticateRequest, InternalAdminAuthenticateResponse, InternalAuthenticateRequest,
    InternalAuthenticateResponse,
};

/// サービス認証トークンのヘッダ名（api 側 `require_service_token` と一致させる）。
const SERVICE_TOKEN_HEADER: &str = "x-internal-auth-token";
/// correlation_id（requestId）の伝播ヘッダ名（api 側 correlation ミドルウェアと一致させる）。
const REQUEST_ID_HEADER: &str = "x-request-id";

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
