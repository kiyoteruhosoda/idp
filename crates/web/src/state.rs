//! web の共有状態（axum `State`）。API クライアントと設定を保持する。

use crate::api_client::ApiClient;
use crate::config::Config;
use crate::cookies::SetCookies;
use crate::service_restart::ServiceRestart;
use std::sync::Arc;

#[derive(Clone)]
pub struct WebState {
    pub config: Arc<Config>,
    pub api: ApiClient,
    /// プロセスの起動時刻。`/internal/health` が稼働時間を出すために持つ（ADR-0031）。
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// 設定画面からの再起動要求（ADR-0017）。`run()` の graceful shutdown がこの値を待つ。
    /// テストでは `build` が作った値を誰も待たないため、要求しても何も起きない。
    pub restart: ServiceRestart,
}

impl WebState {
    pub fn build(config: Arc<Config>) -> Self {
        let api = ApiClient::new(
            config.api_base_url().to_string(),
            config.internal_service_token().to_string(),
        );
        Self {
            config,
            api,
            started_at: chrono::Utc::now(),
            restart: ServiceRestart::new(),
        }
    }

    /// 応答へ載せる `Set-Cookie` の組み立てを始める（属性方針は設定から取る。ADR-0012 §3）。
    pub fn set_cookies(&self) -> SetCookies {
        SetCookies::new(self.config.cookie_policy().clone())
    }

    /// オリジン束縛する web ローカル Cookie（CSRF の種・MFA チケット・SAML 進行状態）の実名。
    ///
    /// HTTPS では `__Host-` を前置し、同一親ドメインの別サブドメインからの上書き・強制を防ぐ
    /// （SEC5）。読み出しと発行の両方でこれを通すこと（片方だけ素の名前を使うと、値が読めずに
    /// 毎回 CSRF 不一致になる）。
    pub fn origin_bound_cookie(&self, base_name: &str) -> String {
        self.config.cookie_policy().origin_bound_name(base_name)
    }
}
