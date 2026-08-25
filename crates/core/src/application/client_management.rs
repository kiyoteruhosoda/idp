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
use crate::domain::client_jwks::{parse_registration_jwks, ClientJwks};
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::message::MessageKey;
use crate::domain::outbound_uri::is_internal_destination;
use crate::domain::paging::{PageRequest, PagedResult};
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
/// クライアント一覧 1 ページの既定件数（G7）。
pub const DEFAULT_PAGE_LIMIT: i64 = 50;
/// クライアント一覧 1 ページの上限件数（過大な取得を防ぐ）。
pub const MAX_PAGE_LIMIT: i64 = 200;

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
    /// `private_key_jwt` の検証鍵（JWK Set の JSON。ADR-0030）。同方式を選ぶ場合は必須で、
    /// それ以外の方式では指定できない。
    pub jwks: Option<String>,
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
    /// `private_key_jwt` の検証鍵の差し替え（ADR-0030）。鍵ローテーションはこの集合へ
    /// 新旧を並べて行う。
    pub jwks: Option<String>,
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
        // 機械（M2M）だけが redirect_uri を持たずに登録できる（ADR-0032）。ブラウザのリダイレクト先が
        // 無い呼び出し元に、使いもしない URL を 1 つ捏造させないための例外である。
        let machine_to_machine =
            cmd.allow_client_credentials && cmd.client_type == ClientType::Confidential;
        let redirect_uris = validate_redirect_uris(&cmd.redirect_uris, machine_to_machine)?;
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
        // `private_key_jwt` は共有秘密を持たない（ADR-0030）。secret を発行しないのは、
        // 使われない秘密を DB に置かないためであると同時に、「登録は private_key_jwt だが
        // secret でも通る」という併存を作らないためでもある。
        let (auth_method, secret_plain, secret_hash, jwks) = match cmd.client_type {
            ClientType::Public => {
                if cmd.jwks.is_some() {
                    return Err(ClientManagementError::Validation(MessageKey::new(
                        "api-client-jwks-not-applicable",
                    )));
                }
                (TokenEndpointAuthMethod::None, None, None, None)
            }
            ClientType::Confidential => {
                let method = validate_confidential_auth_method(cmd.token_endpoint_auth_method)?;
                let jwks = validate_jwks_for_method(method, cmd.jwks.as_deref())?;
                if method == TokenEndpointAuthMethod::PrivateKeyJwt {
                    (method, None, None, jwks)
                } else {
                    let plain = crate::domain::crypto::random_token(CLIENT_SECRET_BYTES);
                    let hash = self
                        .hasher
                        .hash(&plain)
                        .map_err(|e| ClientManagementError::Internal(e.to_string()))?;
                    (method, Some(plain), Some(hash), jwks)
                }
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
            // ブラウザ経由の利用者ログインは Authorization Code Flow のみ（設計仕様 §5）。
            // `client_credentials` は M2M 用の追加許可で、confidential のみ受け付ける（G4）。
            grant_types: grant_types_for(
                cmd.client_type,
                cmd.allow_client_credentials,
                !redirect_uris.is_empty(),
            ),
            redirect_uris,
            response_types: vec!["code".to_string()],
            scopes,
            token_endpoint_auth_method: auth_method,
            jwks,
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

    /// 登録済みクライアントを 1 ページ分返す（G7）。`limit` / `offset` は未検証の要求値を
    /// 受け取り、許容範囲へ収めたうえで**適用値**を結果に添える。
    pub async fn list_page(
        &self,
        tenant: TenantContext,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<PagedResult<Client>, ClientManagementError> {
        let request = PageRequest::clamped(limit, offset, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);
        let page = self
            .clients
            .list_page(tenant.tenant_id(), request)
            .await
            .map_err(|e| ClientManagementError::Internal(e.to_string()))?;
        Ok(PagedResult::new(page, request))
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
        // 認証方式の**切り替え**にだけ課す前提条件（secret / 検証鍵の有無）を判定するために覚えておく。
        // 方式を変えていない更新（app_name の修正など）で資格情報を書き換えないためでもある。
        let method_before = client.token_endpoint_auth_method;

        if let Some(app_name) = cmd.app_name {
            client.app_name = validate_app_name(app_name)?;
        }
        // redirect_uri を空にできるかは `client_credentials` の可否で決まるので、更新後の姿で判定する
        // （この更新で許可を外しつつ URI も消す、という組み合わせを通さないため）。ADR-0032。
        let allows_client_credentials = cmd
            .allow_client_credentials
            .unwrap_or_else(|| client.allows_client_credentials())
            && client.client_type == ClientType::Confidential;
        if let Some(redirect_uris) = cmd.redirect_uris {
            client.redirect_uris =
                validate_redirect_uris(&redirect_uris, allows_client_credentials)?;
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
        // grant_types は登録内容から導出する値であって、独立に持つ設定ではない（ADR-0032）。
        // 更新のたびに引き直すことで、redirect_uri を消したのに `authorization_code` が残る、
        // といった実態と合わない組み合わせが生まれない。
        client.grant_types = grant_types_for(
            client.client_type,
            allows_client_credentials,
            !client.redirect_uris.is_empty(),
        );
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
        // 検証鍵の差し替え（ADR-0030）。方式の変更と同時に指定できるよう、方式の反映後に見る。
        if let Some(raw) = cmd.jwks.as_deref() {
            if client.token_endpoint_auth_method != TokenEndpointAuthMethod::PrivateKeyJwt {
                return Err(ClientManagementError::Validation(MessageKey::new(
                    "api-client-jwks-not-applicable",
                )));
            }
            client.jwks = Some(parse_jwks(raw)?);
        }
        let switched = client.token_endpoint_auth_method != method_before;
        match client.token_endpoint_auth_method {
            TokenEndpointAuthMethod::PrivateKeyJwt => {
                // 検証鍵が無いまま `private_key_jwt` にすると、そのクライアントはどの資格情報でも
                // 認証できなくなる。鍵は既存でも今回の指定でもよい。
                if client.jwks.is_none() {
                    return Err(ClientManagementError::Validation(MessageKey::new(
                        "api-client-jwks-required",
                    )));
                }
                // 切り替えた時点で、以後読まれない共有秘密を落とす。secret 方式へ戻すときは
                // `rotate_secret` で再発行する。方式を変えていない更新では触らない
                // （切り替えの前準備として再発行しておいた secret を、無関係な更新で消さないため）。
                if switched {
                    client.client_secret_hash = None;
                }
            }
            // secret 方式へ切り替えるなら照合できる secret が要る。無いまま切り替えると認証
            // できなくなるため、先に再発行（`rotate_secret`）してから切り替えてもらう。
            TokenEndpointAuthMethod::ClientSecretBasic
            | TokenEndpointAuthMethod::ClientSecretPost => {
                if switched && client.client_secret_hash.is_none() {
                    return Err(ClientManagementError::Validation(MessageKey::new(
                        "api-client-auth-method-needs-secret",
                    )));
                }
                // secret 方式では検証鍵を持たない（読まれない鍵を残さない）。
                client.jwks = None;
            }
            // public（`none`）。資格情報を持たない。
            TokenEndpointAuthMethod::None => client.jwks = None,
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
        Some(TokenEndpointAuthMethod::PrivateKeyJwt) => Ok(TokenEndpointAuthMethod::PrivateKeyJwt),
        Some(TokenEndpointAuthMethod::None) => Err(ClientManagementError::Validation(
            MessageKey::new("api-client-auth-method-invalid"),
        )),
    }
}

/// 登録時の検証鍵を、選ばれた認証方式と突き合わせる（ADR-0030）。
///
/// `private_key_jwt` では必須、それ以外では指定を拒否する（黙って捨てると、鍵を登録したつもりの
/// 管理者に「登録できた」と伝わってしまう）。
fn validate_jwks_for_method(
    method: TokenEndpointAuthMethod,
    raw: Option<&str>,
) -> Result<Option<ClientJwks>, ClientManagementError> {
    match (method, raw) {
        (TokenEndpointAuthMethod::PrivateKeyJwt, Some(raw)) => Ok(Some(parse_jwks(raw)?)),
        (TokenEndpointAuthMethod::PrivateKeyJwt, None) => Err(ClientManagementError::Validation(
            MessageKey::new("api-client-jwks-required"),
        )),
        (_, Some(_)) => Err(ClientManagementError::Validation(MessageKey::new(
            "api-client-jwks-not-applicable",
        ))),
        (_, None) => Ok(None),
    }
}

fn parse_jwks(raw: &str) -> Result<ClientJwks, ClientManagementError> {
    parse_registration_jwks(raw).map_err(|e| ClientManagementError::Validation(e.message_key()))
}

fn grant_types_for(
    client_type: ClientType,
    allow_client_credentials: bool,
    has_redirect_uris: bool,
) -> Vec<String> {
    let mut grants = Vec::new();
    // redirect_uri を持たないクライアントで認可フローは成立しない（`/authorize` は要求された
    // redirect_uri を登録値と突き合わせる）。付けても使えない許可が残るだけなので付けない。
    if has_redirect_uris {
        grants.push(GrantType::AuthorizationCode.as_str().to_string());
    }
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
fn validate_redirect_uris(
    uris: &[String],
    machine_to_machine: bool,
) -> Result<Vec<String>, ClientManagementError> {
    if uris.is_empty() {
        // M2M 以外で空を許すと、認可フローも M2M も使えない「何もできないクライアント」ができる。
        return if machine_to_machine {
            Ok(Vec::new())
        } else {
            Err(ClientManagementError::Validation(MessageKey::new(
                "api-client-redirect-uris-empty",
            )))
        };
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
        // 利用者ログインをするクライアントでは 1 つ以上必要（空では認可フローが成立しない）。
        assert!(validate_redirect_uris(&[], false).is_err());
        assert!(validate_redirect_uris(
            &[
                "https://a.example.com/cb".to_string(),
                "https://a.example.com/cb".to_string(),
            ],
            false
        )
        .is_err());
    }

    /// ADR-0032: 機械（M2M）はブラウザのリダイレクト先を持たないので空を許す。
    #[test]
    fn machine_to_machine_clients_may_omit_redirect_uris() {
        assert_eq!(
            validate_redirect_uris(&[], true).expect("empty is ok"),
            Vec::<String>::new()
        );
        // 例外は「空を許す」だけで、指定された URI の検査は緩めない。
        assert!(validate_redirect_uris(&["not-a-url".to_string()], true).is_err());
    }

    /// grant_types は「実際にできること」から導出する（ADR-0032）。
    #[test]
    fn grant_types_follow_what_the_client_can_actually_do() {
        // 利用者ログインのみ。
        assert_eq!(
            grant_types_for(ClientType::Confidential, false, true),
            vec!["authorization_code".to_string()]
        );
        // 機械のみ —— redirect_uri が無いので `authorization_code` は付かない。
        assert_eq!(
            grant_types_for(ClientType::Confidential, true, false),
            vec!["client_credentials".to_string()]
        );
        // 両方。
        assert_eq!(
            grant_types_for(ClientType::Confidential, true, true),
            vec![
                "authorization_code".to_string(),
                "client_credentials".to_string()
            ]
        );
        // public は秘密を秘匿できないため、許可されていても M2M は付かない。
        assert_eq!(
            grant_types_for(ClientType::Public, true, true),
            vec!["authorization_code".to_string()]
        );
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
