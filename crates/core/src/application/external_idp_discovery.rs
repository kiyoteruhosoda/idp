//! 外部 IdP（OIDC）の discovery ドキュメント取り込み（task #77）。
//!
//! 管理者が入れた issuer から `{issuer}/.well-known/openid-configuration` を読み、登録フォームの
//! 初期値（`authorization_endpoint` / `token_endpoint` / `jwks_uri`）を返す。**取り込みは登録ではない**
//! ——何も保存せず、監査にも残さない（SAML の IdP メタデータ取り込みと同じ扱い）。登録は、
//! 管理者が値を確かめてから `ExternalIdpManagementService::register` で行う。
//!
//! 順番が要である。
//!
//! 1. 宛先の検査（[`DiscoveryUrl::for_issuer`]。https のみ・内部宛先を拒否）。**通らなければ
//!    外へは 1 回も出ない。**
//! 2. 取得（[`OidcDiscoveryClient`]。リダイレクトを追わない・タイムアウト・大きさの上限）
//! 3. 文書の検証（[`OidcDiscoveryDocument::verify_for`]。`issuer` の完全一致と、各エンドポイントの検査）
//!
//! [`OidcDiscoveryDocument::verify_for`]: crate::domain::oidc_discovery::OidcDiscoveryDocument::verify_for

use crate::domain::error::DomainError;
use crate::domain::external_oidc_port::OidcDiscoveryClient;
use crate::domain::oidc_discovery::{DiscoveryUrl, ImportedOidcProvider};
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum DiscoveryImportError {
    /// 入力（issuer）か、取得した文書が受け入れられない（宛先の検査・`issuer` 不一致・項目の欠落）。
    #[error("validation error: {0}")]
    Validation(String),
    /// 文書を取得できなかった（届かない・2xx 以外・リダイレクト・大きすぎる・JSON でない）。
    #[error("discovery document unavailable: {0}")]
    Unavailable(String),
}

pub struct ExternalIdpDiscoveryService {
    client: Arc<dyn OidcDiscoveryClient>,
}

impl ExternalIdpDiscoveryService {
    pub fn new(client: Arc<dyn OidcDiscoveryClient>) -> Self {
        Self { client }
    }

    /// issuer の discovery ドキュメントを読み、登録候補値を返す（保存はしない）。
    pub async fn import(&self, issuer: &str) -> Result<ImportedOidcProvider, DiscoveryImportError> {
        let url = DiscoveryUrl::for_issuer(issuer).map_err(validation)?;
        let document = self
            .client
            .fetch_discovery(&url)
            .await
            .map_err(|e| match e {
                // 取得の実装は、接続段の詳細（届かない理由）を運用ログにだけ残し、ここへは返さない。
                DomainError::Repository(m) => DiscoveryImportError::Unavailable(m),
                other => DiscoveryImportError::Unavailable(other.to_string()),
            })?;
        document.verify_for(&url).map_err(validation)
    }
}

fn validation(e: DomainError) -> DiscoveryImportError {
    match e {
        DomainError::InvalidValue(m) => DiscoveryImportError::Validation(m),
        other => DiscoveryImportError::Validation(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::Result;
    use crate::domain::oidc_discovery::OidcDiscoveryDocument;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// 取得を記録するだけの偽物。宛先の検査より前に外へ出ていないことを確かめるのに使う。
    struct RecordingClient {
        document: std::result::Result<OidcDiscoveryDocument, String>,
        fetched: Mutex<Vec<String>>,
    }

    impl RecordingClient {
        fn returning(document: std::result::Result<OidcDiscoveryDocument, String>) -> Arc<Self> {
            Arc::new(Self {
                document,
                fetched: Mutex::new(Vec::new()),
            })
        }

        fn fetched(&self) -> Vec<String> {
            self.fetched.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl OidcDiscoveryClient for RecordingClient {
        async fn fetch_discovery(&self, url: &DiscoveryUrl) -> Result<OidcDiscoveryDocument> {
            self.fetched.lock().unwrap().push(url.as_str().to_string());
            match &self.document {
                Ok(d) => Ok(d.clone()),
                Err(m) => Err(DomainError::Repository(m.clone())),
            }
        }
    }

    fn document(issuer: &str) -> OidcDiscoveryDocument {
        OidcDiscoveryDocument {
            issuer: Some(issuer.to_string()),
            authorization_endpoint: Some("https://idp.example.com/authorize".to_string()),
            token_endpoint: Some("https://idp.example.com/token".to_string()),
            jwks_uri: Some("https://idp.example.com/jwks".to_string()),
        }
    }

    #[tokio::test]
    async fn the_document_under_the_issuer_is_imported() {
        let client = RecordingClient::returning(Ok(document("https://idp.example.com")));
        let imported = ExternalIdpDiscoveryService::new(client.clone())
            .import("https://idp.example.com")
            .await
            .expect("import");
        assert_eq!(imported.token_endpoint, "https://idp.example.com/token");
        assert_eq!(
            client.fetched(),
            vec!["https://idp.example.com/.well-known/openid-configuration"]
        );
    }

    /// 宛先の検査に通らない issuer では**外へ 1 回も出ない**（SSRF を作らない）。
    #[tokio::test]
    async fn internal_destinations_are_never_fetched() {
        for issuer in [
            "http://idp.example.com",
            "https://169.254.169.254",
            "https://127.0.0.1:8443",
            "https://localhost",
            "https://192.168.1.10",
        ] {
            let client = RecordingClient::returning(Ok(document(issuer)));
            let err = ExternalIdpDiscoveryService::new(client.clone())
                .import(issuer)
                .await
                .expect_err("must be rejected");
            assert!(
                matches!(err, DiscoveryImportError::Validation(_)),
                "{issuer}: {err}"
            );
            assert!(client.fetched().is_empty(), "{issuer} must not be fetched");
        }
    }

    #[tokio::test]
    async fn an_issuer_mismatch_is_rejected() {
        let client = RecordingClient::returning(Ok(document("https://evil.example.com")));
        let err = ExternalIdpDiscoveryService::new(client)
            .import("https://idp.example.com")
            .await
            .expect_err("mismatch");
        assert!(
            matches!(&err, DiscoveryImportError::Validation(m) if m.contains("does not match")),
            "{err}"
        );
    }

    /// 取得の失敗は `Validation` と分ける（入力の誤りではなく、相手の文書が取れなかった）。
    #[tokio::test]
    async fn fetch_failures_are_reported_as_unavailable() {
        let client = RecordingClient::returning(Err(
            "discovery endpoint returned 404 Not Found".to_string()
        ));
        let err = ExternalIdpDiscoveryService::new(client)
            .import("https://idp.example.com")
            .await
            .expect_err("unavailable");
        assert!(
            matches!(&err, DiscoveryImportError::Unavailable(m) if m.contains("404")),
            "{err}"
        );
    }
}
