//! クライアント（RP）登録・管理のユースケース（設計仕様 §9.3、Progress A1）。
//!
//! 管理者（`idp.admin`）のみが実行する。`client_id` は自動採番、`client_secret` は confidential
//! クライアントに対して発行し**初回（および再発行時）のみ平文を返す**。DB には argon2 ハッシュのみ
//! 保存する（既存 `PasswordHasher` を流用）。全ての変更操作は `audit_log` に記録する。
//!
//! redirect URI は完全一致・複数登録に対応し、フラグメント／ワイルドカードを禁止する（§2.3）。
//! 要求 scope の部分集合判定に用いる `Clients.scopes` は、対応する OIDC scope の集合に限定する。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::client::Client;
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::password::PasswordHasher;
use crate::domain::repositories::ClientRepository;
use crate::domain::values::{ClientStatus, ClientType, Scope, TokenEndpointAuthMethod};
use std::sync::Arc;
use uuid::Uuid;

/// 発行する client_id のバイト長（小文字 16 進で 2 倍の文字数になる）。
const CLIENT_ID_BYTES: usize = 16;
/// 発行する client_secret のバイト長（256bit）。
const CLIENT_SECRET_BYTES: usize = 32;

#[derive(Debug, Clone)]
pub struct RegisterClientCommand {
    pub app_name: String,
    pub client_type: ClientType,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    /// 省略時は既定（true）。public は PKCE 必須のため false を指定しても true に矯正する。
    pub require_pkce: Option<bool>,
    /// RP-initiated logout 後のリダイレクト先（任意）。F4。
    pub post_logout_redirect_uris: Vec<String>,
    /// front-channel logout URI（任意）。F4。
    pub frontchannel_logout_uri: Option<String>,
    /// back-channel logout URI（任意）。F4。
    pub backchannel_logout_uri: Option<String>,
}

/// 部分更新コマンド。`None` のフィールドは変更しない。
#[derive(Debug, Clone, Default)]
pub struct UpdateClientCommand {
    pub app_name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub status: Option<ClientStatus>,
    /// RP-initiated logout 後のリダイレクト先（`Some(vec![])` で削除）。F4。
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// front-channel logout URI（`Some(None)` で削除）。F4。
    pub frontchannel_logout_uri: Option<Option<String>>,
    /// back-channel logout URI（`Some(None)` で削除）。F4。
    pub backchannel_logout_uri: Option<Option<String>>,
}

/// 登録結果。`client_secret` は confidential のときのみ平文で返る（保存はハッシュのみ）。
pub struct RegisteredClient {
    pub client: Client,
    pub client_secret: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientManagementError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct ClientManagementService {
    clients: Arc<dyn ClientRepository>,
    hasher: Arc<dyn PasswordHasher>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl ClientManagementService {
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        hasher: Arc<dyn PasswordHasher>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            clients,
            hasher,
            audit,
            clock,
        }
    }

    pub async fn register(
        &self,
        cmd: RegisterClientCommand,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<RegisteredClient, ClientManagementError> {
        let app_name = validate_app_name(cmd.app_name)?;
        let redirect_uris = validate_redirect_uris(&cmd.redirect_uris)?;
        let scopes = validate_scopes(&cmd.scopes)?;

        // client 種別に応じて認証方式・PKCE・secret を決める。
        // public: 認証なし・PKCE 必須・secret なし。confidential: client_secret_basic・secret 発行。
        let (auth_method, require_pkce, secret_plain, secret_hash) = match cmd.client_type {
            ClientType::Public => (TokenEndpointAuthMethod::None, true, None, None),
            ClientType::Confidential => {
                let plain = crate::infrastructure::crypto::random_token(CLIENT_SECRET_BYTES);
                let hash = self
                    .hasher
                    .hash(&plain)
                    .map_err(|e| ClientManagementError::Internal(e.to_string()))?;
                (
                    TokenEndpointAuthMethod::ClientSecretBasic,
                    cmd.require_pkce.unwrap_or(true),
                    Some(plain),
                    Some(hash),
                )
            }
        };

        let now = self.clock.now();
        let client = Client {
            id: Uuid::new_v4(),
            client_id: crate::infrastructure::crypto::random_hex(CLIENT_ID_BYTES),
            client_secret_hash: secret_hash,
            client_type: cmd.client_type,
            client_status: ClientStatus::Active,
            app_name,
            redirect_uris,
            // MVP は Authorization Code Flow のみ対応（設計仕様 §5）。
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            scopes,
            token_endpoint_auth_method: auth_method,
            require_pkce,
            post_logout_redirect_uris: cmd.post_logout_redirect_uris,
            frontchannel_logout_uri: cmd.frontchannel_logout_uri,
            backchannel_logout_uri: cmd.backchannel_logout_uri,
            created_at: now,
            updated_at: now,
        };

        self.clients.create(&client).await.map_err(|e| match e {
            DomainError::Conflict(m) => ClientManagementError::Conflict(m),
            other => ClientManagementError::Internal(other.to_string()),
        })?;

        self.audit
            .record(
                AuditEventType::ClientRegistered,
                AuditResult::Success,
                Some(actor),
                Some(&client.client_id),
                None,
                ctx,
            )
            .await;

        Ok(RegisteredClient {
            client,
            client_secret: secret_plain,
        })
    }

    pub async fn list(&self) -> Result<Vec<Client>, ClientManagementError> {
        self.clients
            .list()
            .await
            .map_err(|e| ClientManagementError::Internal(e.to_string()))
    }

    pub async fn get(&self, client_id: &str) -> Result<Client, ClientManagementError> {
        self.load(client_id).await
    }

    pub async fn update(
        &self,
        client_id: &str,
        cmd: UpdateClientCommand,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<Client, ClientManagementError> {
        let mut client = self.load(client_id).await?;

        if let Some(app_name) = cmd.app_name {
            client.app_name = validate_app_name(app_name)?;
        }
        if let Some(redirect_uris) = cmd.redirect_uris {
            client.redirect_uris = validate_redirect_uris(&redirect_uris)?;
        }
        if let Some(scopes) = cmd.scopes {
            client.scopes = validate_scopes(&scopes)?;
        }
        if let Some(status) = cmd.status {
            client.client_status = status;
        }
        if let Some(uris) = cmd.post_logout_redirect_uris {
            client.post_logout_redirect_uris = uris;
        }
        if let Some(uri) = cmd.frontchannel_logout_uri {
            client.frontchannel_logout_uri = uri;
        }
        if let Some(uri) = cmd.backchannel_logout_uri {
            client.backchannel_logout_uri = uri;
        }

        self.clients
            .update(&client)
            .await
            .map_err(|e| ClientManagementError::Internal(e.to_string()))?;

        self.audit
            .record(
                AuditEventType::ClientUpdated,
                AuditResult::Success,
                Some(actor),
                Some(&client.client_id),
                None,
                ctx,
            )
            .await;

        Ok(client)
    }

    /// client_secret を再発行する（confidential のみ）。新しい平文を返し、DB はハッシュのみ更新する。
    pub async fn rotate_secret(
        &self,
        client_id: &str,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<(Client, String), ClientManagementError> {
        let mut client = self.load(client_id).await?;
        if client.client_type != ClientType::Confidential {
            return Err(ClientManagementError::Validation(
                "only confidential clients have a secret".to_string(),
            ));
        }

        let plain = crate::infrastructure::crypto::random_token(CLIENT_SECRET_BYTES);
        client.client_secret_hash = Some(
            self.hasher
                .hash(&plain)
                .map_err(|e| ClientManagementError::Internal(e.to_string()))?,
        );

        self.clients
            .update(&client)
            .await
            .map_err(|e| ClientManagementError::Internal(e.to_string()))?;

        self.audit
            .record(
                AuditEventType::ClientSecretRotated,
                AuditResult::Success,
                Some(actor),
                Some(&client.client_id),
                None,
                ctx,
            )
            .await;

        Ok((client, plain))
    }

    async fn load(&self, client_id: &str) -> Result<Client, ClientManagementError> {
        self.clients
            .find_by_client_id(client_id)
            .await
            .map_err(|e| ClientManagementError::Internal(e.to_string()))?
            .ok_or(ClientManagementError::NotFound)
    }
}

fn validate_app_name(app_name: String) -> Result<String, ClientManagementError> {
    let trimmed = app_name.trim().to_string();
    if trimmed.is_empty() {
        return Err(ClientManagementError::Validation(
            "app_name must not be empty".to_string(),
        ));
    }
    Ok(trimmed)
}

/// redirect URI 群を検証する。1 件以上・重複なし・各 URI が §2.3 の制約を満たすこと。
fn validate_redirect_uris(uris: &[String]) -> Result<Vec<String>, ClientManagementError> {
    if uris.is_empty() {
        return Err(ClientManagementError::Validation(
            "at least one redirect_uri is required".to_string(),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(uris.len());
    for uri in uris {
        validate_redirect_uri(uri)?;
        if !seen.insert(uri.as_str()) {
            return Err(ClientManagementError::Validation(format!(
                "duplicate redirect_uri: {uri}"
            )));
        }
        out.push(uri.clone());
    }
    Ok(out)
}

/// 単一 redirect URI の制約（設計仕様 §2.3）: 絶対 http(s) URL・フラグメント禁止・ワイルドカード禁止。
fn validate_redirect_uri(uri: &str) -> Result<(), ClientManagementError> {
    if uri.contains('*') {
        return Err(ClientManagementError::Validation(format!(
            "redirect_uri must not contain a wildcard: {uri}"
        )));
    }
    let parsed = url::Url::parse(uri)
        .map_err(|_| ClientManagementError::Validation(format!("invalid redirect_uri: {uri}")))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ClientManagementError::Validation(format!(
            "redirect_uri scheme must be http or https: {uri}"
        )));
    }
    if parsed.fragment().is_some() {
        return Err(ClientManagementError::Validation(format!(
            "redirect_uri must not contain a fragment: {uri}"
        )));
    }
    Ok(())
}

/// scope 群を検証する。1 件以上・既知の OIDC scope のみ・`openid` を含み・重複なしであること。
fn validate_scopes(scopes: &[String]) -> Result<Vec<String>, ClientManagementError> {
    if scopes.is_empty() {
        return Err(ClientManagementError::Validation(
            "at least one scope is required".to_string(),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for scope in scopes {
        Scope::parse(scope).map_err(|_| {
            ClientManagementError::Validation(format!("unsupported scope: {scope}"))
        })?;
        if !seen.insert(scope.as_str()) {
            return Err(ClientManagementError::Validation(format!(
                "duplicate scope: {scope}"
            )));
        }
    }
    if !scopes.iter().any(|s| s == Scope::OpenId.as_str()) {
        return Err(ClientManagementError::Validation(
            "scopes must include `openid`".to_string(),
        ));
    }
    Ok(scopes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_redirect_uris() {
        assert!(validate_redirect_uri("https://app.example.com/callback").is_ok());
        assert!(validate_redirect_uri("http://localhost:3000/cb").is_ok());
    }

    #[test]
    fn rejects_bad_redirect_uris() {
        assert!(validate_redirect_uri("https://app.example.com/cb#frag").is_err());
        assert!(validate_redirect_uri("https://app.example.com/*").is_err());
        assert!(validate_redirect_uri("ftp://app.example.com/cb").is_err());
        assert!(validate_redirect_uri("not-a-url").is_err());
        assert!(validate_redirect_uri("/relative/path").is_err());
    }

    #[test]
    fn rejects_empty_and_duplicate_redirect_uris() {
        assert!(validate_redirect_uris(&[]).is_err());
        assert!(validate_redirect_uris(&[
            "https://a.example.com/cb".to_string(),
            "https://a.example.com/cb".to_string(),
        ])
        .is_err());
    }

    #[test]
    fn scopes_must_be_known_include_openid_and_unique() {
        assert!(validate_scopes(&["openid".to_string(), "email".to_string()]).is_ok());
        assert!(validate_scopes(&["email".to_string()]).is_err()); // openid 無し
        assert!(validate_scopes(&["openid".to_string(), "admin".to_string()]).is_err()); // 未知
        assert!(validate_scopes(&["openid".to_string(), "openid".to_string()]).is_err()); // 重複
        assert!(validate_scopes(&[]).is_err());
    }

    #[test]
    fn app_name_is_trimmed_and_non_empty() {
        assert_eq!(validate_app_name("  App  ".to_string()).unwrap(), "App");
        assert!(validate_app_name("   ".to_string()).is_err());
    }
}
