//! クライアント（RP）登録・管理のユースケース（設計仕様 §9.3、Progress A1）。
//!
//! テナント管理者（`idp.tenant.admin`。`idp.system.admin` は代替として許可）のみが実行する。`client_id` は自動採番、`client_secret` は confidential
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
use crate::domain::id_generator::IdGenerator;
use crate::domain::message::MessageKey;
use crate::domain::outbound_uri::is_internal_destination;
use crate::domain::password::PasswordHasher;
use crate::domain::repositories::ClientRepository;
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::{ClientStatus, ClientType, GrantType, Scope, TokenEndpointAuthMethod};
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
    /// サーバ間（M2M）連携で `client_credentials` grant を使えるようにするか（G4。既定 false）。
    /// public client は資格情報を秘匿できないため、指定されても無効のまま登録する。
    pub allow_client_credentials: bool,
    /// confidential client のクライアント認証方式（G3）。`None` は既定の `client_secret_basic`。
    /// public client には適用しない（常に `none`）。
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,
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
    /// `client_credentials` grant の許可（G4）。public client には適用しない。
    pub allow_client_credentials: Option<bool>,
    /// クライアント認証方式の変更（G3）。confidential client のみ。
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,
}

/// 登録結果。`client_secret` は confidential のときのみ平文で返る（保存はハッシュのみ）。
pub struct RegisteredClient {
    pub client: Client,
    pub client_secret: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientManagementError {
    #[error("validation error: {0}")]
    Validation(MessageKey),
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(MessageKey),
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct ClientManagementService {
    clients: Arc<dyn ClientRepository>,
    hasher: Arc<dyn PasswordHasher>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl ClientManagementService {
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        hasher: Arc<dyn PasswordHasher>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            clients,
            hasher,
            audit,
            clock,
            ids,
        }
    }

    pub async fn register(
        &self,
        tenant: TenantContext,
        cmd: RegisterClientCommand,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<RegisteredClient, ClientManagementError> {
        let app_name = validate_app_name(cmd.app_name)?;
        let redirect_uris = validate_redirect_uris(&cmd.redirect_uris)?;
        let scopes = validate_scopes(&cmd.scopes)?;
        // ログアウト系 URI も redirect URI と同じ検査を通す（SEC2）。
        let post_logout_redirect_uris =
            validate_post_logout_redirect_uris(&cmd.post_logout_redirect_uris)?;
        let frontchannel_logout_uri =
            validate_frontchannel_logout_uri(cmd.frontchannel_logout_uri)?;
        let backchannel_logout_uri = validate_backchannel_logout_uri(cmd.backchannel_logout_uri)?;

        // client 種別に応じて認証方式・secret を決める。
        // public: 認証なし・secret なし。confidential: secret 発行 + 提示方式の選択（G3）。
        // PKCE（S256）は種別によらず `/authorize`・`/token` が無条件に要求する（クライアント単位の
        // 設定は持たない。SEC12 で「実際には参照されない設定」を削除した）。
        let (auth_method, secret_plain, secret_hash) = match cmd.client_type {
            ClientType::Public => (TokenEndpointAuthMethod::None, None, None),
            ClientType::Confidential => {
                let method = validate_confidential_auth_method(cmd.token_endpoint_auth_method)?;
                let plain = crate::domain::crypto::random_token(CLIENT_SECRET_BYTES);
                let hash = self
                    .hasher
                    .hash(&plain)
                    .map_err(|e| ClientManagementError::Internal(e.to_string()))?;
                (method, Some(plain), Some(hash))
            }
        };

        let now = self.clock.now();
        let client = Client {
            id: self.ids.new_id(),
            tenant_id: tenant.tenant_id(),
            client_id: crate::domain::crypto::random_hex(CLIENT_ID_BYTES),
            client_secret_hash: secret_hash,
            client_type: cmd.client_type,
            client_status: ClientStatus::Active,
            app_name,
            redirect_uris,
            // ブラウザ経由の利用者ログインは Authorization Code Flow のみ（設計仕様 §5）。
            // `client_credentials` は M2M 用の追加許可で、confidential のみ受け付ける（G4）。
            grant_types: grant_types_for(cmd.client_type, cmd.allow_client_credentials),
            response_types: vec!["code".to_string()],
            scopes,
            token_endpoint_auth_method: auth_method,
            post_logout_redirect_uris,
            frontchannel_logout_uri,
            backchannel_logout_uri,
            created_at: now,
            updated_at: now,
        };

        self.clients.create(&client).await.map_err(|e| match e {
            // DB の一意制約違反はテナント内の client_id 重複しかない（他の一意キーを持たない）。
            DomainError::Conflict(_) => {
                ClientManagementError::Conflict(MessageKey::new("api-client-id-conflict"))
            }
            other => ClientManagementError::Internal(other.to_string()),
        })?;

        self.audit
            .record(
                AuditEventType::ClientRegistered,
                AuditResult::Success,
                Some(tenant.tenant_id()),
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

    pub async fn list(&self, tenant: TenantContext) -> Result<Vec<Client>, ClientManagementError> {
        self.clients
            .list(tenant.tenant_id())
            .await
            .map_err(|e| ClientManagementError::Internal(e.to_string()))
    }

    pub async fn get(
        &self,
        tenant: TenantContext,
        client_id: &str,
    ) -> Result<Client, ClientManagementError> {
        self.load(tenant, client_id).await
    }

    pub async fn update(
        &self,
        tenant: TenantContext,
        client_id: &str,
        cmd: UpdateClientCommand,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<Client, ClientManagementError> {
        let mut client = self.load(tenant, client_id).await?;

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
        // 更新時も登録時と同じ検査を通す（SEC2。登録を通しても更新で差し替えられては意味がない）。
        if let Some(uris) = cmd.post_logout_redirect_uris {
            client.post_logout_redirect_uris = validate_post_logout_redirect_uris(&uris)?;
        }
        if let Some(uri) = cmd.frontchannel_logout_uri {
            client.frontchannel_logout_uri = validate_frontchannel_logout_uri(uri)?;
        }
        if let Some(uri) = cmd.backchannel_logout_uri {
            client.backchannel_logout_uri = validate_backchannel_logout_uri(uri)?;
        }
        if let Some(allow) = cmd.allow_client_credentials {
            client.grant_types = grant_types_for(client.client_type, allow);
        }
        // 認証方式の変更は confidential のみ（G3）。public は secret を持たないため `none` 固定で、
        // 指定は黙って無視せず拒否する（「変えたつもりで変わっていない」状態を作らない）。
        if let Some(method) = cmd.token_endpoint_auth_method {
            if client.client_type != ClientType::Confidential {
                return Err(ClientManagementError::Validation(MessageKey::new(
                    "api-client-auth-method-public",
                )));
            }
            client.token_endpoint_auth_method = validate_confidential_auth_method(Some(method))?;
        }

        self.clients
            .update(&client)
            .await
            .map_err(|e| ClientManagementError::Internal(e.to_string()))?;

        self.audit
            .record(
                AuditEventType::ClientUpdated,
                AuditResult::Success,
                Some(tenant.tenant_id()),
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
        tenant: TenantContext,
        client_id: &str,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<(Client, String), ClientManagementError> {
        let mut client = self.load(tenant, client_id).await?;
        if client.client_type != ClientType::Confidential {
            return Err(ClientManagementError::Validation(MessageKey::new(
                "api-client-secret-public",
            )));
        }

        let plain = crate::domain::crypto::random_token(CLIENT_SECRET_BYTES);
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
                Some(tenant.tenant_id()),
                Some(actor),
                Some(&client.client_id),
                None,
                ctx,
            )
            .await;

        Ok((client, plain))
    }

    async fn load(
        &self,
        tenant: TenantContext,
        client_id: &str,
    ) -> Result<Client, ClientManagementError> {
        self.clients
            .find_by_client_id(tenant.tenant_id(), client_id)
            .await
            .map_err(|e| ClientManagementError::Internal(e.to_string()))?
            .ok_or(ClientManagementError::NotFound)
    }
}

/// クライアントへ付与する grant_type の集合を決める（G4）。
///
/// `authorization_code` は全クライアント共通の基本許可。`client_credentials` は confidential かつ
/// 管理者が明示的に有効化したときだけ足す（public client は指定されても付けない）。`refresh_token`
/// は `offline_access` scope の同意で制御しており grant_types では絞らない（従来どおり）。
/// confidential client のクライアント認証方式を検証する（G3）。
///
/// 省略時は RFC 6749 §2.3.1 が推奨する `client_secret_basic`。`none`（＝認証なし）は
/// confidential では選べない —— 選べてしまうと secret を持ったまま誰でも `/token` を叩ける
/// クライアントが管理画面から作れてしまう。
fn validate_confidential_auth_method(
    requested: Option<TokenEndpointAuthMethod>,
) -> Result<TokenEndpointAuthMethod, ClientManagementError> {
    match requested {
        None => Ok(TokenEndpointAuthMethod::ClientSecretBasic),
        Some(TokenEndpointAuthMethod::ClientSecretBasic) => {
            Ok(TokenEndpointAuthMethod::ClientSecretBasic)
        }
        Some(TokenEndpointAuthMethod::ClientSecretPost) => {
            Ok(TokenEndpointAuthMethod::ClientSecretPost)
        }
        Some(TokenEndpointAuthMethod::None) => Err(ClientManagementError::Validation(
            MessageKey::new("api-client-auth-method-invalid"),
        )),
    }
}

fn grant_types_for(client_type: ClientType, allow_client_credentials: bool) -> Vec<String> {
    let mut grants = vec![GrantType::AuthorizationCode.as_str().to_string()];
    if allow_client_credentials && client_type == ClientType::Confidential {
        grants.push(GrantType::ClientCredentials.as_str().to_string());
    }
    grants
}

fn validate_app_name(app_name: String) -> Result<String, ClientManagementError> {
    let trimmed = app_name.trim().to_string();
    if trimmed.is_empty() {
        return Err(ClientManagementError::Validation(MessageKey::new(
            "api-client-app-name-empty",
        )));
    }
    Ok(trimmed)
}

/// redirect URI 群を検証する。1 件以上・重複なし・各 URI が §2.3 の制約を満たすこと。
fn validate_redirect_uris(uris: &[String]) -> Result<Vec<String>, ClientManagementError> {
    if uris.is_empty() {
        return Err(ClientManagementError::Validation(MessageKey::new(
            "api-client-redirect-uris-empty",
        )));
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(uris.len());
    for uri in uris {
        validate_redirect_uri(uri)?;
        if !seen.insert(uri.as_str()) {
            return Err(ClientManagementError::Validation(MessageKey::with_value(
                "api-client-redirect-uri-duplicate",
                uri,
            )));
        }
        out.push(uri.clone());
    }
    Ok(out)
}

/// URI 種別ごとの検証エラーの翻訳キー束。
///
/// `MessageKey` のキーは静的文字列に限る（動的キーは訳の抜けを静かに増やす）ため、
/// 検証ロジックを共有しつつ文言だけを種別ごとに差し替える。
struct UriMessageKeys {
    invalid: &'static str,
    scheme: &'static str,
    fragment: &'static str,
    wildcard: &'static str,
    duplicate: &'static str,
}

const REDIRECT_URI_KEYS: UriMessageKeys = UriMessageKeys {
    invalid: "api-client-redirect-uri-invalid",
    scheme: "api-client-redirect-uri-scheme",
    fragment: "api-client-redirect-uri-fragment",
    wildcard: "api-client-redirect-uri-wildcard",
    duplicate: "api-client-redirect-uri-duplicate",
};

/// ログアウト系 URI（`post_logout_redirect_uris` / `frontchannel_logout_uri` /
/// `backchannel_logout_uri`）用のキー束。
const LOGOUT_URI_KEYS: UriMessageKeys = UriMessageKeys {
    invalid: "api-client-logout-uri-invalid",
    scheme: "api-client-logout-uri-scheme",
    fragment: "api-client-logout-uri-fragment",
    wildcard: "api-client-logout-uri-wildcard",
    duplicate: "api-client-logout-uri-duplicate",
};

/// 単一 redirect URI の制約（設計仕様 §2.3）: 絶対 http(s) URL・フラグメント禁止・ワイルドカード禁止。
fn validate_redirect_uri(uri: &str) -> Result<(), ClientManagementError> {
    validate_absolute_web_uri(uri, &REDIRECT_URI_KEYS).map(|_| ())
}

/// 絶対 http(s) URL・フラグメント禁止・ワイルドカード禁止を検証し、解析済み URL を返す。
fn validate_absolute_web_uri(
    uri: &str,
    keys: &UriMessageKeys,
) -> Result<url::Url, ClientManagementError> {
    if uri.contains('*') {
        return Err(ClientManagementError::Validation(MessageKey::with_value(
            keys.wildcard,
            uri,
        )));
    }
    let parsed = url::Url::parse(uri).map_err(|_| {
        ClientManagementError::Validation(MessageKey::with_value(keys.invalid, uri))
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ClientManagementError::Validation(MessageKey::with_value(
            keys.scheme,
            uri,
        )));
    }
    if parsed.fragment().is_some() {
        return Err(ClientManagementError::Validation(MessageKey::with_value(
            keys.fragment,
            uri,
        )));
    }
    Ok(parsed)
}

/// `post_logout_redirect_uris` を検証する（SEC2）。0 件は許容（機能を使わない）。
///
/// ブラウザのリダイレクト先であり `redirect_uris` と同じ危険（オープンリダイレクト・
/// スキーム悪用）を持つため、同じ制約を課す。
fn validate_post_logout_redirect_uris(
    uris: &[String],
) -> Result<Vec<String>, ClientManagementError> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(uris.len());
    for uri in uris {
        let uri = uri.trim();
        if uri.is_empty() {
            continue;
        }
        validate_absolute_web_uri(uri, &LOGOUT_URI_KEYS)?;
        if !seen.insert(uri.to_string()) {
            return Err(ClientManagementError::Validation(MessageKey::with_value(
                LOGOUT_URI_KEYS.duplicate,
                uri,
            )));
        }
        out.push(uri.to_string());
    }
    Ok(out)
}

/// `frontchannel_logout_uri` を検証する（SEC2）。空文字は「未設定」として扱う。
///
/// ブラウザが iframe で読み込む URL なので、リダイレクト先と同じ制約で足りる
/// （IdP のサーバからは接続しないため SSRF にはならない）。
fn validate_frontchannel_logout_uri(
    uri: Option<String>,
) -> Result<Option<String>, ClientManagementError> {
    let Some(uri) = uri.map(|u| u.trim().to_string()).filter(|u| !u.is_empty()) else {
        return Ok(None);
    };
    validate_absolute_web_uri(&uri, &LOGOUT_URI_KEYS)?;
    Ok(Some(uri))
}

/// `backchannel_logout_uri` を検証する（SEC2）。空文字は「未設定」として扱う。
///
/// **api がサーバ側から POST する唯一の外向き URI** であり、テナント管理者権限で任意の宛先を
/// 登録できると認証済み blind SSRF（クラウドメタデータ・内部管理 API への到達）になる。
/// リダイレクト先と同じ形式制約に加え、プライベート・ループバック・リンクローカル等の
/// アドレスリテラルを拒否する。
///
/// なお、これは登録時の検査であり、名前解決の結果が内部アドレスになる DNS 由来の到達
/// （DNS rebinding を含む）までは防げない。閉じたい配置では前段プロキシの egress 制御を併用する。
fn validate_backchannel_logout_uri(
    uri: Option<String>,
) -> Result<Option<String>, ClientManagementError> {
    let Some(uri) = uri.map(|u| u.trim().to_string()).filter(|u| !u.is_empty()) else {
        return Ok(None);
    };
    validate_absolute_web_uri(&uri, &LOGOUT_URI_KEYS)?;
    if is_internal_destination(&uri) {
        return Err(ClientManagementError::Validation(MessageKey::with_value(
            "api-client-backchannel-logout-uri-internal-host",
            &uri,
        )));
    }
    Ok(Some(uri))
}

/// scope 群を検証する。1 件以上・既知の OIDC scope のみ・`openid` を含み・重複なしであること。
fn validate_scopes(scopes: &[String]) -> Result<Vec<String>, ClientManagementError> {
    if scopes.is_empty() {
        return Err(ClientManagementError::Validation(MessageKey::new(
            "api-client-scopes-empty",
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for scope in scopes {
        Scope::parse(scope).map_err(|_| {
            ClientManagementError::Validation(MessageKey::with_value(
                "api-client-scope-unsupported",
                scope,
            ))
        })?;
        if !seen.insert(scope.as_str()) {
            return Err(ClientManagementError::Validation(MessageKey::with_value(
                "api-client-scope-duplicate",
                scope,
            )));
        }
    }
    if !scopes.iter().any(|s| s == Scope::OpenId.as_str()) {
        return Err(ClientManagementError::Validation(MessageKey::new(
            "api-client-scopes-missing-openid",
        )));
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

    // ── SEC2: ログアウト系 URI の検証 ────────────────────────────────────────

    #[test]
    fn post_logout_redirect_uris_follow_the_redirect_uri_rules() {
        // 0 件は「機能を使わない」なので許容する。空文字は無視する。
        assert!(validate_post_logout_redirect_uris(&[]).unwrap().is_empty());
        assert!(validate_post_logout_redirect_uris(&["  ".to_string()])
            .unwrap()
            .is_empty());

        assert_eq!(
            validate_post_logout_redirect_uris(&[
                " https://app.example.com/after-logout ".to_string()
            ])
            .unwrap(),
            vec!["https://app.example.com/after-logout".to_string()]
        );

        for bad in [
            "https://app.example.com/x#frag",
            "https://app.example.com/*",
            "javascript:alert(1)",
            "not-a-url",
        ] {
            assert!(
                validate_post_logout_redirect_uris(&[bad.to_string()]).is_err(),
                "{bad} must be rejected"
            );
        }
        assert!(validate_post_logout_redirect_uris(&[
            "https://a.example.com/out".to_string(),
            "https://a.example.com/out".to_string(),
        ])
        .is_err());
    }

    #[test]
    fn frontchannel_logout_uri_is_validated_and_empty_means_unset() {
        assert_eq!(validate_frontchannel_logout_uri(None).unwrap(), None);
        assert_eq!(
            validate_frontchannel_logout_uri(Some("  ".to_string())).unwrap(),
            None
        );
        assert_eq!(
            validate_frontchannel_logout_uri(Some("https://app.example.com/fc".to_string()))
                .unwrap(),
            Some("https://app.example.com/fc".to_string())
        );
        assert!(validate_frontchannel_logout_uri(Some("file:///etc/passwd".to_string())).is_err());
        // ブラウザが読み込むだけなので、プライベート宛でも SSRF にはならない（拒否しない）。
        assert!(
            validate_frontchannel_logout_uri(Some("http://127.0.0.1:9000/fc".to_string())).is_ok()
        );
    }

    #[test]
    fn backchannel_logout_uri_rejects_internal_destinations() {
        assert_eq!(validate_backchannel_logout_uri(None).unwrap(), None);
        assert_eq!(
            validate_backchannel_logout_uri(Some("https://rp.example.com/bc".to_string())).unwrap(),
            Some("https://rp.example.com/bc".to_string())
        );
        // 名前で指す内部サービスは（解決結果を見ないため）通す。
        assert!(validate_backchannel_logout_uri(Some("http://rp:3000/bc".to_string())).is_ok());

        for bad in [
            // クラウドのインスタンスメタデータ（link-local）。
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8080/internal",
            "http://localhost/internal",
            "http://app.LOCALHOST/internal",
            "http://10.0.0.5/admin",
            "http://192.168.1.1/admin",
            "http://172.16.0.1/admin",
            "http://100.64.0.1/admin",
            "http://0.0.0.0/",
            "http://[::1]/internal",
            "http://[fd00::1]/internal",
            "http://[fe80::1]/internal",
            "http://[::ffff:127.0.0.1]/internal",
        ] {
            assert!(
                validate_backchannel_logout_uri(Some(bad.to_string())).is_err(),
                "{bad} must be rejected as an internal destination"
            );
        }
    }
}
