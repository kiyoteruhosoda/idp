//! ブラウザからの越境アクセス（CORS）で許可するオリジンの決定（G1）。
//!
//! 既定トポロジは `domain-split`（api と web が別ホスト名）なので、SPA が
//! `identity.example.com/{tenant}/token` を呼ぶのは**常にクロスオリジン**である。
//! `clients.client_type = 'public'` と `token_endpoint_auth_method = 'none'` を DDL で受け入れ
//! PKCE を必須にしている以上、想定利用者は SPA だが、`Access-Control-Allow-Origin` が無いために
//! ブラウザがレスポンスを読めず実質到達できなかった。
//!
//! # なぜ「テナント内の public クライアントのオリジン集合」なのか
//!
//! 経路によってクライアントを特定できるかが違う:
//!
//! - `/.well-known/*`・`/saml/metadata` は `client_id` もトークンも載らない（誰でも取得できる公開
//!   メタデータなので `*` でよい。これは [`ApiCorsPolicy`] ではなく presentation 側で扱う）。
//! - `/userinfo` は `Authorization: Bearer` が非 safelisted ヘッダのため**必ずプリフライトされる**が、
//!   OPTIONS にトークンは載らない。つまりリクエストからクライアントを特定できない。
//! - `/token`・`/revoke`・`/introspect` は body の `client_id` から特定**できる**。
//!
//! 特定できる経路だけ厳密にしても得るものが無いため、判定はテナント単位に揃える。
//! オリジンを 1 つ広く許しても、`Access-Control-Allow-Credentials` を**付けない**以上
//! ブラウザは Cookie を載せず、`/token` は code と PKCE の `code_verifier`、`/userinfo` は
//! アクセストークンを別途要求する。つまり「同一テナントの別 public クライアントのオリジンから
//! 応答を読めてしまう」ことに実質的な意味は無い（読むための資格情報を持たない）。
//! 判定を揃えることで、プリフライトと実リクエストで許可集合が食い違う事故も避けられる。

use crate::domain::cache::Cache;
use crate::domain::repositories::ClientRepository;
use crate::domain::tenant::TenantId;
use crate::domain::values::ClientType;
use std::sync::Arc;

/// CORS で許可するオリジンの決定。
pub struct ApiCorsPolicy {
    clients: Arc<dyn ClientRepository>,
    /// 配置レベルで明示的に許可するオリジン（`CORS_ALLOWED_ORIGINS`）。全テナント共通。
    configured_origins: Vec<String>,
    /// テナント → 許可オリジン集合。`/token`・`/userinfo` はホットパスのため都度 SELECT しない。
    cache: Arc<dyn Cache<TenantId, Arc<Vec<String>>>>,
}

impl ApiCorsPolicy {
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        configured_origins: Vec<String>,
        cache: Arc<dyn Cache<TenantId, Arc<Vec<String>>>>,
    ) -> Self {
        Self {
            clients,
            configured_origins,
            cache,
        }
    }

    /// `origin` がこのテナントで許可されているか。
    ///
    /// 一致は**完全一致**（スキーム・ホスト・ポート）で行う。`redirect_uri` の完全一致検証と
    /// 同じ厳密さであり、サフィックス一致のような緩い判定は入れない。
    pub async fn allows(&self, tenant_id: TenantId, origin: &str) -> bool {
        if origin.is_empty() {
            return false;
        }
        if self.configured_origins.iter().any(|o| o == origin) {
            return true;
        }
        self.tenant_origins(tenant_id)
            .await
            .iter()
            .any(|o| o == origin)
    }

    /// テナント内の public クライアントの `redirect_uris` から導いたオリジン集合。
    async fn tenant_origins(&self, tenant_id: TenantId) -> Arc<Vec<String>> {
        if let Some(hit) = self.cache.get(&tenant_id) {
            return hit;
        }
        let origins = match self.clients.list(tenant_id).await {
            Ok(clients) => Arc::new(collect_public_client_origins(&clients)),
            Err(e) => {
                // 失敗しても許可集合を「空」として扱う（開いてしまうより閉じる）。キャッシュには
                // 載せない（次のリクエストで引き直す）。
                tracing::error!(error = %e, "failed to load clients for the CORS allowlist");
                return Arc::new(Vec::new());
            }
        };
        self.cache.insert(tenant_id, origins.clone());
        origins
    }

    /// クライアント更新時にテナントのオリジン集合を捨てる（管理画面での `redirect_uris` 変更を反映）。
    pub fn invalidate(&self, tenant_id: TenantId) {
        self.cache.invalidate(&tenant_id);
    }
}

/// public クライアントの `redirect_uris` からオリジン（`scheme://host[:port]`）を集める。
///
/// confidential クライアントを含めないのは、そちらがブラウザから直接 `/token` を叩かない
/// （client_secret をブラウザへ置けない）ためである。無効化されたクライアントも除く。
fn collect_public_client_origins(clients: &[crate::domain::client::Client]) -> Vec<String> {
    let mut origins: Vec<String> = clients
        .iter()
        .filter(|c| c.client_type == ClientType::Public && c.is_active())
        .flat_map(|c| c.redirect_uris.iter())
        .filter_map(|uri| origin_of(uri))
        .collect();
    origins.sort();
    origins.dedup();
    origins
}

/// URI からブラウザが `Origin` ヘッダに載せる形（`scheme://host[:port]`。既定ポートは省略）へ。
///
/// `http://localhost:3000/callback` → `http://localhost:3000`
/// カスタムスキーム（`myapp://...`。ネイティブアプリの redirect）は `Origin` に現れないため除く。
fn origin_of(uri: &str) -> Option<String> {
    let parsed = url::Url::parse(uri).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?;
    match parsed.port() {
        // `Url::port()` は既定ポート（80/443）を `None` として返すため、ここに来るのは非既定のみ。
        Some(port) => Some(format!("{}://{host}:{port}", parsed.scheme())),
        None => Some(format!("{}://{host}", parsed.scheme())),
    }
}

/// 設定値（カンマ区切り）を許可オリジンの一覧へ。空白と末尾スラッシュは落とす。
pub fn parse_configured_origins(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().trim_end_matches('/'))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ports_are_omitted_like_the_browser_does() {
        assert_eq!(
            origin_of("https://app.example.com/callback").as_deref(),
            Some("https://app.example.com")
        );
        assert_eq!(
            origin_of("https://app.example.com:443/callback").as_deref(),
            Some("https://app.example.com")
        );
        assert_eq!(
            origin_of("http://localhost:3000/callback").as_deref(),
            Some("http://localhost:3000")
        );
    }

    /// ネイティブアプリの redirect（カスタムスキーム・loopback 以外）は `Origin` に現れないので
    /// 許可集合へ入れない。入れても効かないうえ、意図が読めない値が並ぶ。
    #[test]
    fn custom_schemes_are_not_origins() {
        assert_eq!(origin_of("com.example.app://callback"), None);
        assert_eq!(origin_of("not a url"), None);
    }

    #[test]
    fn configured_origins_are_trimmed_and_normalised() {
        assert_eq!(
            parse_configured_origins(" https://a.example.com/ , https://b.example.com ,, "),
            vec!["https://a.example.com", "https://b.example.com"]
        );
        assert!(parse_configured_origins("").is_empty());
    }
}
