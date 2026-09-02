//! トークン発行のユースケース（`POST /token`、設計仕様 §4.4・§5・§9.1）。
//!
//! - `authorization_code` grant: client 認証 → code の原子的 one-time 消費 →
//!   各種一致検証 → PKCE S256 検証 → ID Token / Access Token（RS256）発行。
//!   scope に `offline_access` が含まれる場合は Refresh Token も発行する。
//! - `refresh_token` grant: client 認証 → Refresh Token の検証 → rotation →
//!   reuse detection → 新 Access Token / ID Token 発行。
//! - `client_credentials` grant（G4）: client 認証 → grant 許可の確認 → scope 検証 →
//!   Access Token のみ発行。利用者が居ないフローなので **ID Token も Refresh Token も出さない**
//!   （OIDC Core は ID Token を「エンドユーザーの認証結果」と定めており、認証していない主体に
//!   発行してはならない）。`sub` はクライアント自身（`client_id`）で、利用者主体のトークンと
//!   取り違えないよう `sub_type` クレームで明示する。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::client_authentication::{
    ClientAuthError, ClientAuthFailure, ClientAuthOutcome, ClientAuthenticator,
    PresentedClientCredentials,
};
use crate::application::key_service::KeyService;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::client::Client;
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::OAuthErrorCode;
use crate::domain::issuer::tenant_issuer;
use crate::domain::jwt;
use crate::domain::pkce;
use crate::domain::refresh_token::RefreshToken;
use crate::domain::repositories::{
    AuthorizationCodeRepository, ClientPermissionRepository, ClientRepository,
    ClientResourceRepository, ProtectedResourceRepository, RefreshTokenRepository,
    TenantRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::Scope;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// ID Token のクレーム（設計仕様 §5.1）。任意クレームは scope に応じて付与する。
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub auth_time: i64,
    pub nonce: String,
    pub jti: String,
    /// SSO セッション識別子（OIDC Back-Channel Logout 1.0 §2.1。G5）。RP はこの値で
    /// 「どのセッションのログアウト通知か」を突き合わせ、セッション単位で失効できる。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// `sub_type` クレームの値: 主体がクライアント自身（`client_credentials` grant。G4）。
///
/// クレーム自体が無い場合はエンドユーザー主体（従来のトークン）。値ではなく**有無**で区別すること
/// で、本クレーム導入前に発行済みのトークンも従来どおり利用者主体として扱える。
pub const SUBJECT_TYPE_CLIENT: &str = "client";

/// Access Token のクレーム（設計仕様 §5.2）。`aud` は `/userinfo` に固定する。
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub client_id: String,
    pub scope: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    /// 主体の種別（G4）。`client_credentials` で発行したトークンだけが
    /// [`SUBJECT_TYPE_CLIENT`] を持つ。省略 = エンドユーザー主体。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_type: Option<String>,
    /// assay 自身の管理 API に対する権限コード（空白区切り。ADR-0037）。
    ///
    /// **`aud` が [`management_audience`] のトークンにしか載せない。** 権限コードは assay の
    /// API を守るためのものであって、他のリソースサーバの権限体系ではない（ADR-0033）。`aud` を
    /// 管理 API に固定することで、外部アプリ向けのトークンへ権限コードが流れ込む経路が無くなる。
    ///
    /// OIDC の `scope` と分けるのも同じ理由である。`scope` は ID クレームの制御に使う値で、
    /// RP がその内容に依存し得る。混ぜると管理権限が RP の認可判断へ漏れる。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perms: Option<String>,
}

impl AccessTokenClaims {
    /// 主体がクライアント自身か（`client_credentials` で発行されたトークンか）。
    pub fn subject_is_client(&self) -> bool {
        self.sub_type.as_deref() == Some(SUBJECT_TYPE_CLIENT)
    }
}

/// `/userinfo` 用 Access Token の `aud` を構築する（issuer は末尾スラッシュ無し）。
pub fn userinfo_audience(issuer: &str) -> String {
    format!("{issuer}/userinfo")
}

/// assay 自身の管理 API 用 Access Token の `aud` を構築する（ADR-0037）。
///
/// `/userinfo` 向けと別の値にすることが要である。同じ `aud` にすると、RP が利用者ログインで
/// 受け取ったトークンをそのまま管理 API へ持ち込めてしまう（`perms` が空なので通らないとはいえ、
/// 「audience が合っている」という前提を管理面と共有すべきではない）。
pub fn management_audience(issuer: &str) -> String {
    format!("{issuer}/admin")
}

#[derive(Debug, Default)]
pub struct TokenCommand {
    pub grant_type: Option<String>,
    /// `authorization_code` grant 専用。
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    /// 提示されたクライアント資格情報（`Authorization: Basic` / body の `client_id`・`client_secret`）。
    pub credentials: PresentedClientCredentials,
    /// `refresh_token` grant 専用。
    pub refresh_token: Option<String>,
    /// `client_credentials` grant で要求する scope（空白区切り）。省略時はクライアントの登録 scope
    /// から既定集合を導く（G4）。
    pub scope: Option<String>,
    /// 要求するリソース指標（RFC 8707 `resource`。ADR-0037）。
    ///
    /// assay の管理 API を呼ぶシステム用クライアントは、`{issuer}/admin` を指定して
    /// 管理トークンを受け取る。省略時は従来どおり `/userinfo` 向けのトークンを発行する。
    /// **どちらを欲しいのかを呼び出し側に書かせる**のは、クライアントの登録権限から発行内容を
    /// 暗黙に切り替えると、権限を 1 つ付けた途端にトークンの `aud` が変わってしまうためである。
    pub resource: Option<String>,
}

/// トークンエンドポイントのエラー（RFC 6749 §5.2 形式で返す）。
#[derive(Debug)]
pub struct TokenError {
    pub code: OAuthErrorCode,
    pub description: String,
}

impl TokenError {
    fn new(code: OAuthErrorCode, description: &str) -> Self {
        Self {
            code,
            description: description.to_string(),
        }
    }
}

pub struct IssuedTokens {
    pub access_token: String,
    /// 利用者を認証した grant（`authorization_code` / `refresh_token`）でのみ発行する。
    /// `client_credentials` は利用者が居ないため `None`（G4）。
    pub id_token: Option<String>,
    pub expires_in: u64,
    pub scope: String,
    /// `offline_access` scope が含まれる場合のみ発行する。
    pub refresh_token: Option<String>,
}

pub struct TokenService {
    clients: Arc<dyn ClientRepository>,
    users: Arc<dyn UserRepository>,
    /// 利用者の**所属元**テナントの状態を見るために持つ（ADR-0009 §8）。要求テナントの解決は
    /// presentation（`TenantResolver`）が済ませているので、ここで見るのは所属元だけ。
    tenants: Arc<dyn TenantRepository>,
    codes: Arc<dyn AuthorizationCodeRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    /// システム用クライアントが保有する管理 API の権限コード（ADR-0037）。`resource` に管理 API を
    /// 指定された `client_credentials` でのみ引く。
    client_permissions: Arc<dyn ClientPermissionRepository>,
    /// 登録済みの宛名（`aud` に入る値。ADR-0042）。`resource` に assay 自身以外を指定された
    /// `client_credentials` でのみ引く。
    resources: Arc<dyn ProtectedResourceRepository>,
    /// クライアントへ許した宛名（ADR-0042）。登録されているだけでは足りず、要求元が
    /// その宛先を要求してよいかをここで確かめる。
    client_resources: Arc<dyn ClientResourceRepository>,
    keys: Arc<KeyService>,
    /// クライアント認証（secret 照合・assertion 検証）。方式ごとの分岐は
    /// `client_authentication` に集約してある（ADR-0030）。
    client_auth: Arc<ClientAuthenticator>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    /// 基底 issuer（`https://<host>`）。`iss` はテナント毎に `<基底>/<tenant_id>` を合成する
    /// （ADR-0009 §6。`domain::issuer::tenant_issuer`）。
    base_issuer: String,
    access_token_ttl: std::time::Duration,
    /// 管理 API 向けアクセストークン（`resource={issuer}/admin`）の寿命（ADR-0037）。
    /// 通常のアクセストークンより短く保つ。
    management_token_ttl: std::time::Duration,
    id_token_ttl: std::time::Duration,
    refresh_token_ttl: std::time::Duration,
}

impl TokenService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        users: Arc<dyn UserRepository>,
        tenants: Arc<dyn TenantRepository>,
        codes: Arc<dyn AuthorizationCodeRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        client_permissions: Arc<dyn ClientPermissionRepository>,
        resources: Arc<dyn ProtectedResourceRepository>,
        client_resources: Arc<dyn ClientResourceRepository>,
        keys: Arc<KeyService>,
        client_auth: Arc<ClientAuthenticator>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        base_issuer: String,
        access_token_ttl: std::time::Duration,
        management_token_ttl: std::time::Duration,
        id_token_ttl: std::time::Duration,
        refresh_token_ttl: std::time::Duration,
    ) -> Self {
        Self {
            clients,
            users,
            tenants,
            codes,
            refresh_tokens,
            client_permissions,
            resources,
            client_resources,
            keys,
            client_auth,
            audit,
            clock,
            base_issuer,
            access_token_ttl,
            management_token_ttl,
            id_token_ttl,
            refresh_token_ttl,
        }
    }

    pub async fn exchange(
        &self,
        tenant: TenantContext,
        cmd: TokenCommand,
        ctx: &RequestContext,
    ) -> Result<IssuedTokens, TokenError> {
        // `resource`（RFC 8707）を解釈するのは `client_credentials` だけである（ADR-0037）。
        // 利用者を認証した grant で管理トークンを出すことは無いので、黙って無視すると
        // 「管理トークンを頼んだのに `/userinfo` 用が返り、管理 API で 401 になる」という、
        // 原因が要求側から見えない失敗になる。要求の時点で断る。
        if cmd
            .resource
            .as_deref()
            .is_some_and(|r| !r.trim().is_empty())
            && cmd.grant_type.as_deref() != Some("client_credentials")
        {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidTarget,
                "the `resource` parameter is only supported for the client_credentials grant",
            ));
        }
        match cmd.grant_type.as_deref() {
            Some("authorization_code") => self.exchange_code(tenant, cmd, ctx).await,
            Some("refresh_token") => self.exchange_refresh_token(tenant, cmd, ctx).await,
            Some("client_credentials") => self.issue_client_credentials(tenant, cmd, ctx).await,
            _ => Err(TokenError::new(
                OAuthErrorCode::UnsupportedGrantType,
                "grant_type must be `authorization_code`, `refresh_token` or `client_credentials`",
            )),
        }
    }

    /// `authorization_code` grant の処理。
    async fn exchange_code(
        &self,
        tenant: TenantContext,
        cmd: TokenCommand,
        ctx: &RequestContext,
    ) -> Result<IssuedTokens, TokenError> {
        let tenant_id = tenant.tenant_id();
        // 1. client_id の決定（Basic ヘッダ優先）。
        let client_id = resolve_client_id(&cmd)?;

        // 2. client の存在・状態・認証（フローのテナントに属する client のみ解決する）。
        let client = self.load_active_client(tenant, &client_id, ctx).await?;
        self.authenticate_client(tenant, &client, &cmd, ctx).await?;

        // 3. code_verifier の形式検証（RFC 7636 §4.1）。
        let Some(code_verifier) = cmd.code_verifier.as_deref().filter(|v| !v.is_empty()) else {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidRequest,
                "code_verifier is required",
            ));
        };
        if !pkce::is_valid_code_verifier(code_verifier) {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidRequest,
                "code_verifier must be 43-128 characters of [A-Za-z0-9-._~]",
            ));
        }

        // 4. code の原子的 one-time 消費。
        let Some(code) = cmd.code.as_deref().filter(|c| !c.is_empty()) else {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidRequest,
                "code is required",
            ));
        };
        let now = self.clock.now();
        // code の hash は消費とファミリ鍵（`grant_hash`。SEC8）の両方で使うので 1 度だけ計算する。
        let code_hash = crypto::sha256_hex(code);
        let consumed = match self.codes.consume(tenant_id, &code_hash, now).await {
            Ok(c) => c,
            Err(e) => return Err(internal(&e)),
        };
        let Some(auth_code) = consumed else {
            // 消費できなかった理由を切り分ける（SEC8）。「期限切れ」「そもそも存在しない」と
            // **本当の再利用**（1 度交換済みの code をもう一度出してきた）は意味が違い、
            // 前者は RP の実装ミスや遅延、後者は code の漏えいを示す。1 文字列に丸めていると
            // 監査から攻撃を拾えない。
            let used_code = match self.codes.find_used(tenant_id, &code_hash).await {
                Ok(v) => v,
                Err(e) => return Err(internal(&e)),
            };
            let (reason, used_code) = match used_code {
                Some(used) => {
                    // 本当の再利用。1 回目の交換で発行済みのトークンファミリを失効させる。
                    // 攻撃者と正規 RP のどちらが先に交換したか区別できない以上、両方を止めて
                    // 再認証させるのが RFC 6819 §5.2.1.1 の求めるところ。
                    let revoked = match self
                        .refresh_tokens
                        .revoke_family(tenant_id, &code_hash, now)
                        .await
                    {
                        Ok(n) => n,
                        Err(e) => return Err(internal(&e)),
                    };
                    (
                        format!("authorization code replayed; revoked {revoked} refresh token(s)"),
                        Some(used),
                    )
                }
                None => ("authorization code not found or expired".to_string(), None),
            };
            self.audit
                .record(
                    AuditEventType::AuthorizationCodeReuseDetected,
                    AuditResult::Failure,
                    Some(tenant_id),
                    used_code.map(|c| c.user_id),
                    Some(&client_id),
                    Some(&reason),
                    ctx,
                )
                .await;
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "authorization code is invalid, expired, or already used",
            ));
        };
        self.audit
            .record(
                AuditEventType::AuthorizationCodeUsed,
                AuditResult::Success,
                Some(tenant_id),
                Some(auth_code.user_id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;

        // 5. client_id / redirect_uri の一致検証。
        if auth_code.client_id != client_id {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "authorization code was issued to another client",
            ));
        }
        if cmd.redirect_uri.as_deref() != Some(auth_code.redirect_uri.as_str()) {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "redirect_uri does not match the authorization request",
            ));
        }

        // 6. PKCE S256 検証。
        if !pkce::verify_s256(code_verifier, &auth_code.code_challenge) {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "PKCE verification failed",
            ));
        }

        // 7. ユーザーの状態確認。
        let user = self.load_active_user(auth_code.user_id, ctx).await?;

        // 8. トークン発行（scope は AuthorizationCodes.scope を引き継ぐ）。
        let has_offline = auth_code
            .scope
            .iter()
            .any(|v| v == Scope::OfflineAccess.as_str());
        let has = |s: Scope| auth_code.scope.iter().any(|v| v == s.as_str());
        let scope_str = auth_code.scope.join(" ");
        let iat = now.timestamp();
        // `iss` はテナント毎に合成する（ADR-0009 §6）。発行テナント（= フローのテナント）に束縛する。
        let issuer = tenant_issuer(&self.base_issuer, tenant_id);

        let id_claims = IdTokenClaims {
            iss: issuer.clone(),
            sub: user.sub.to_string(),
            aud: client_id.clone(),
            exp: iat + self.id_token_ttl.as_secs() as i64,
            iat,
            auth_time: auth_code.auth_time.timestamp(),
            nonce: auth_code.nonce.clone(),
            jti: Uuid::new_v4().to_string(),
            sid: auth_code.sid.clone(),
            email: has(Scope::Email).then(|| user.email.clone()),
            email_verified: has(Scope::Email).then_some(user.email_verified),
            preferred_username: has(Scope::Profile)
                .then(|| user.preferred_username.clone())
                .flatten(),
            name: has(Scope::Profile).then(|| user.name.clone()).flatten(),
        };
        let access_claims = AccessTokenClaims {
            iss: issuer.clone(),
            sub: user.sub.to_string(),
            aud: userinfo_audience(&issuer),
            client_id: client_id.clone(),
            scope: scope_str.clone(),
            exp: iat + self.access_token_ttl.as_secs() as i64,
            iat,
            jti: Uuid::new_v4().to_string(),
            sub_type: None,
            // 利用者ログインのトークンは管理 API 向けではない（ADR-0037）。
            perms: None,
        };
        let id_token = self.sign_id_token(&id_claims).await?;
        let access_token = self.sign_access_token(&access_claims).await?;

        // 9. Refresh Token 発行（offline_access scope のときのみ）。
        let refresh_token_plain = if has_offline {
            let plain = crypto::random_token(32);
            let rt = RefreshToken {
                token_hash: crypto::sha256_hex(&plain),
                parent_hash: None,
                // このグラント（authorization code）由来のトークンファミリの起点（SEC8）。
                // rotation で子孫へ引き継がれ、code / refresh のどちらの再利用検知からも
                // 同じ鍵で一括失効できる。
                grant_hash: Some(code_hash.clone()),
                tenant_id,
                user_id: auth_code.user_id,
                client_id: client_id.clone(),
                scope: auth_code.scope.clone(),
                // ID Token の `sid`（G5）。rotation でも引き継ぎ、logout_token と同じセッションを指す。
                sid: auth_code.sid.clone(),
                expires_at: now + chrono::Duration::from_std(self.refresh_token_ttl).unwrap(),
                revoked_at: None,
                created_at: now,
            };
            if let Err(e) = self.refresh_tokens.create(&rt).await {
                return Err(internal(&e));
            }
            self.audit
                .record(
                    AuditEventType::RefreshTokenIssued,
                    AuditResult::Success,
                    Some(tenant_id),
                    Some(auth_code.user_id),
                    Some(&client_id),
                    None,
                    ctx,
                )
                .await;
            Some(plain)
        } else {
            None
        };

        self.audit
            .record(
                AuditEventType::TokenIssued,
                AuditResult::Success,
                Some(tenant_id),
                Some(auth_code.user_id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;

        Ok(IssuedTokens {
            access_token,
            id_token: Some(id_token),
            expires_in: self.access_token_ttl.as_secs(),
            scope: scope_str,
            refresh_token: refresh_token_plain,
        })
    }

    /// `refresh_token` grant の処理（rotation + reuse detection）。
    async fn exchange_refresh_token(
        &self,
        tenant: TenantContext,
        cmd: TokenCommand,
        ctx: &RequestContext,
    ) -> Result<IssuedTokens, TokenError> {
        let tenant_id = tenant.tenant_id();
        // 1. client_id の決定・認証。
        let client_id = resolve_client_id(&cmd)?;
        let client = self.load_active_client(tenant, &client_id, ctx).await?;
        self.authenticate_client(tenant, &client, &cmd, ctx).await?;

        // 2. refresh_token パラメータの取り出し。
        let Some(rt_plain) = cmd.refresh_token.as_deref().filter(|v| !v.is_empty()) else {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidRequest,
                "refresh_token is required",
            ));
        };
        let rt_hash = crypto::sha256_hex(rt_plain);
        let now = self.clock.now();

        // 3. トークン検索（発行テナントの一致を含む。他テナント発行のトークンは解決しない）。
        let stored = match self.refresh_tokens.find_by_hash(tenant_id, &rt_hash).await {
            Ok(Some(t)) => t,
            Ok(None) => {
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidGrant,
                    "refresh_token not found",
                ));
            }
            Err(e) => return Err(internal(&e)),
        };

        // 4. client_id 一致確認。
        if stored.client_id != client_id {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "refresh_token was issued to another client",
            ));
        }

        // 5. reuse detection: すでに同じトークンから新トークンが発行済みなら全チェーン失効。
        let already_rotated = match self.refresh_tokens.exists_by_parent_hash(&rt_hash).await {
            Ok(v) => v,
            Err(e) => return Err(internal(&e)),
        };
        if already_rotated {
            // このトークンはすでに rotation 済み → 再利用攻撃の可能性。
            // 提示されたトークンだけを失効させると、そこから rotation 済みの**子孫が生き残る**
            // （攻撃者が先に交換していれば攻撃者側が残る）。同一グラント由来のファミリごと失効させ、
            // 正規の RP にも再認証させる（SEC8。RFC 6819 §5.2.2.3 / OAuth 2.1）。
            // 失効に失敗したら 500 を返して落とす（従来は best-effort で握り潰していたが、
            // 「再利用を検知したのに何も失効していない」状態を成功扱いで返してはいけない）。
            let revoked = match self
                .refresh_tokens
                .revoke_family(tenant_id, &stored.family_hash(), now)
                .await
            {
                Ok(n) => n,
                Err(e) => return Err(internal(&e)),
            };
            self.audit
                .record(
                    AuditEventType::RefreshTokenReuseDetected,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(stored.user_id),
                    Some(&client_id),
                    Some(&format!(
                        "refresh token already rotated; revoked {revoked} token(s) in the grant family"
                    )),
                    ctx,
                )
                .await;
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "refresh_token has already been used",
            ));
        }

        // 6. 有効性確認（失効・期限切れ）。
        if !stored.is_valid_at(now) {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "refresh_token is revoked or expired",
            ));
        }

        // 7. ユーザーの状態確認。
        let user = self.load_active_user(stored.user_id, ctx).await?;

        // 8. 旧トークンを失効させる（rotation）。
        if let Err(e) = self.refresh_tokens.revoke(&rt_hash, now).await {
            return Err(internal(&e));
        }

        // 9. 新トークン発行。
        let has = |s: Scope| stored.scope.iter().any(|v| v == s.as_str());
        let scope_str = stored.scope.join(" ");
        let iat = now.timestamp();
        let issuer = tenant_issuer(&self.base_issuer, tenant_id);

        let id_claims = IdTokenClaims {
            iss: issuer.clone(),
            sub: user.sub.to_string(),
            aud: client_id.clone(),
            exp: iat + self.id_token_ttl.as_secs() as i64,
            iat,
            auth_time: iat,       // refresh 時は現在時刻（再認証なし）
            nonce: String::new(), // refresh grant では nonce は不要
            jti: Uuid::new_v4().to_string(),
            // 元の認可で確立したセッションを指し続ける（rotation で引き継いだ値。G5）。
            sid: stored.sid.clone(),
            email: has(Scope::Email).then(|| user.email.clone()),
            email_verified: has(Scope::Email).then_some(user.email_verified),
            preferred_username: has(Scope::Profile)
                .then(|| user.preferred_username.clone())
                .flatten(),
            name: has(Scope::Profile).then(|| user.name.clone()).flatten(),
        };
        let access_claims = AccessTokenClaims {
            iss: issuer.clone(),
            sub: user.sub.to_string(),
            aud: userinfo_audience(&issuer),
            client_id: client_id.clone(),
            scope: scope_str.clone(),
            exp: iat + self.access_token_ttl.as_secs() as i64,
            iat,
            jti: Uuid::new_v4().to_string(),
            sub_type: None,
            // 利用者ログインのトークンは管理 API 向けではない（ADR-0037）。
            perms: None,
        };
        let id_token = self.sign_id_token(&id_claims).await?;
        let access_token = self.sign_access_token(&access_claims).await?;

        // 10. 新 Refresh Token 発行（rotation）。
        let new_rt_plain = crypto::random_token(32);
        let new_rt = RefreshToken {
            token_hash: crypto::sha256_hex(&new_rt_plain),
            parent_hash: Some(rt_hash.clone()),
            // ファミリ識別子を引き継ぐ（SEC8）。移行前の行（`grant_hash` が NULL）なら
            // 提示されたトークンの hash が新しいファミリの起点になる。
            grant_hash: Some(stored.family_hash()),
            tenant_id,
            user_id: stored.user_id,
            client_id: client_id.clone(),
            scope: stored.scope.clone(),
            sid: stored.sid.clone(),
            expires_at: stored.expires_at, // TTL は引き継ぐ（スライドさせない）
            revoked_at: None,
            created_at: now,
        };
        if let Err(e) = self.refresh_tokens.create(&new_rt).await {
            return Err(internal(&e));
        }

        self.audit
            .record(
                AuditEventType::RefreshTokenUsed,
                AuditResult::Success,
                Some(tenant_id),
                Some(stored.user_id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;
        self.audit
            .record(
                AuditEventType::RefreshTokenIssued,
                AuditResult::Success,
                Some(tenant_id),
                Some(stored.user_id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;
        self.audit
            .record(
                AuditEventType::TokenIssued,
                AuditResult::Success,
                Some(tenant_id),
                Some(stored.user_id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;

        Ok(IssuedTokens {
            access_token,
            id_token: Some(id_token),
            expires_in: self.access_token_ttl.as_secs(),
            scope: scope_str,
            refresh_token: Some(new_rt_plain),
        })
    }

    /// `client_credentials` grant の処理（G4。RFC 6749 §4.4）。
    ///
    /// 利用者が居ないフローのため、発行するのは Access Token だけで ID Token も Refresh Token も
    /// 出さない。`sub` はクライアント自身とし、`sub_type` で利用者主体のトークンと区別できるように
    /// する（`/userinfo` はこのトークンを拒否し、`/introspect` はクライアントの状態を見る）。
    async fn issue_client_credentials(
        &self,
        tenant: TenantContext,
        cmd: TokenCommand,
        ctx: &RequestContext,
    ) -> Result<IssuedTokens, TokenError> {
        let tenant_id = tenant.tenant_id();
        // 1. client の存在・状態・認証。public client は `authenticate_client` が素通しするため、
        //    ここでは grant 許可の判定（`allows_client_credentials`）が confidential も強制する。
        let client_id = resolve_client_id(&cmd)?;
        let client = self.load_active_client(tenant, &client_id, ctx).await?;
        self.authenticate_client(tenant, &client, &cmd, ctx).await?;

        // 2. grant 許可の確認。confidential かつ `client_credentials` を登録済みのクライアントのみ。
        if !client.allows_client_credentials() {
            self.audit
                .record(
                    AuditEventType::ClientAuthenticationFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    None,
                    Some(&client_id),
                    Some("client_credentials_not_allowed"),
                    ctx,
                )
                .await;
            return Err(TokenError::new(
                OAuthErrorCode::UnauthorizedClient,
                "client is not allowed to use the client_credentials grant",
            ));
        }

        // 3. scope の決定と検証。省略時はクライアントの登録 scope から既定集合を導く。
        let scopes = resolve_client_credentials_scopes(&client, cmd.scope.as_deref())?;
        let scope_str = scopes.join(" ");

        // 4. 宛先（`resource`）の決定（RFC 8707。ADR-0037 / ADR-0042）。assay 自身の管理 API を
        //    要求された場合だけ、クライアントが保有する権限コードを `perms` に載せた管理トークンを
        //    出す。それ以外は登録済みの宛名（`resources`）を引き、許可されていれば `aud` に載せる。
        //    どちらでもなければ `invalid_target`——**この認可サーバが知らない宛先へは出さない**。
        let now = self.clock.now();
        let iat = now.timestamp();
        let issuer = tenant_issuer(&self.base_issuer, tenant_id);
        let management_aud = management_audience(&issuer);
        // 管理トークンは通常のアクセストークンより短命にする（ADR-0037 決定 2）。`perms` は
        // トークンから読むため、この寿命が「権限を剥奪してから実際に効くまで」の上限になる。
        let (audience, perms, ttl) = match cmd.resource.as_deref().map(str::trim) {
            None | Some("") => (userinfo_audience(&issuer), None, self.access_token_ttl),
            Some(requested) if requested == management_aud => {
                let codes = self
                    .client_permissions
                    .list_codes_for_client(client.id)
                    .await
                    .map_err(|e| internal(&e))?;
                // 権限が 1 つも無いクライアントへ管理トークンを出さない。出しても全部 403 になる
                // トークンであり、「取れたのに何も通らない」という最も追いにくい失敗を生む。
                if codes.is_empty() {
                    self.audit
                        .record(
                            AuditEventType::ClientAuthenticationFailed,
                            AuditResult::Failure,
                            Some(tenant_id),
                            None,
                            Some(&client_id),
                            Some("no_management_permissions"),
                            ctx,
                        )
                        .await;
                    return Err(TokenError::new(
                        OAuthErrorCode::InvalidTarget,
                        "client holds no management permissions for the requested resource",
                    ));
                }
                (
                    management_aud,
                    Some(codes.join(" ")),
                    self.management_token_ttl,
                )
            }
            // 登録済みの宛名（ADR-0042）。ここで `aud` に載るのは**呼ばれる側の名前**で、
            // assay が接続する先ではない。`perms` は載せない——そこで何をしてよいかは
            // リソースサーバが `client_id` で決める（ADR-0033）。
            Some(requested) => {
                let resource = self
                    .resources
                    .find_by_uri(tenant_id, requested)
                    .await
                    .map_err(|e| internal(&e))?;
                // 「登録が無い」「停止中」「許可されていない」を**応答では区別しない**。
                // 区別すると、総当たりで「どの宛名が登録されているか」を探れる。切り分けは監査で行う。
                let reason = match resource.as_ref() {
                    None => Some("unknown_resource"),
                    Some(resource) if !resource.is_active() => Some("resource_disabled"),
                    Some(resource) => {
                        let granted = self
                            .client_resources
                            .is_granted(client.id, resource.id)
                            .await
                            .map_err(|e| internal(&e))?;
                        (!granted).then_some("resource_not_granted")
                    }
                };
                if let Some(reason) = reason {
                    self.audit
                        .record(
                            AuditEventType::ClientAuthenticationFailed,
                            AuditResult::Failure,
                            Some(tenant_id),
                            None,
                            Some(&client_id),
                            Some(reason),
                            ctx,
                        )
                        .await;
                    return Err(TokenError::new(
                        OAuthErrorCode::InvalidTarget,
                        "the requested resource is not served by this authorization server",
                    ));
                }
                (requested.to_string(), None, self.access_token_ttl)
            }
        };

        // 5. Access Token を発行する（ID Token・Refresh Token は出さない）。
        let access_claims = AccessTokenClaims {
            iss: issuer.clone(),
            // 利用者不在のため主体はクライアント自身（RFC 6749 §4.4 の運用慣行）。
            sub: client.client_id.clone(),
            aud: audience,
            client_id: client.client_id.clone(),
            scope: scope_str.clone(),
            exp: iat + ttl.as_secs() as i64,
            iat,
            jti: Uuid::new_v4().to_string(),
            sub_type: Some(SUBJECT_TYPE_CLIENT.to_string()),
            perms,
        };
        let access_token = self.sign_access_token(&access_claims).await?;

        self.audit
            .record(
                AuditEventType::TokenIssued,
                AuditResult::Success,
                Some(tenant_id),
                // 利用者が居ないので user_id は残さない（クライアント自身が主体）。
                None,
                Some(&client.client_id),
                Some("grant=client_credentials"),
                ctx,
            )
            .await;

        Ok(IssuedTokens {
            access_token,
            id_token: None,
            expires_in: ttl.as_secs(),
            scope: scope_str,
            refresh_token: None,
        })
    }

    async fn sign_id_token(&self, claims: &IdTokenClaims) -> Result<String, TokenError> {
        let key = self
            .keys
            .active_signing_key()
            .await
            .map_err(|e| internal(&e))?;
        jwt::sign(&key.private_pem, &key.kid, "JWT", &key.algorithm, claims)
            .map_err(|e| internal(&e))
    }

    async fn sign_access_token(&self, claims: &AccessTokenClaims) -> Result<String, TokenError> {
        let key = self
            .keys
            .active_signing_key()
            .await
            .map_err(|e| internal(&e))?;
        jwt::sign(&key.private_pem, &key.kid, "at+jwt", &key.algorithm, claims)
            .map_err(|e| internal(&e))
    }

    /// クライアント認証（設計仕様 §4.4、RFC 6749 §2.3.1）。
    ///
    /// 照合する資格情報の選択（Basic / body / assertion）も照合そのものも
    /// `client_authentication` へ集約してある（G3・ADR-0030）。ここが担うのは監査記録だけ。
    async fn authenticate_client(
        &self,
        tenant: TenantContext,
        client: &Client,
        cmd: &TokenCommand,
        ctx: &RequestContext,
    ) -> Result<(), TokenError> {
        match self
            .client_auth
            .authenticate(tenant, client, &cmd.credentials)
            .await
        {
            // public client（`none`）は認証なしで通す。
            Ok(ClientAuthOutcome::NotRequired | ClientAuthOutcome::Authenticated) => Ok(()),
            Err(ClientAuthError::Failed(failure)) => Err(self
                .client_auth_failed(tenant, &client.client_id, failure.as_str(), ctx)
                .await),
            Err(ClientAuthError::Internal(message)) => Err(internal(&message)),
        }
    }

    async fn load_active_client(
        &self,
        tenant: TenantContext,
        client_id: &str,
        ctx: &RequestContext,
    ) -> Result<Client, TokenError> {
        match self
            .clients
            .find_by_client_id(tenant.tenant_id(), client_id)
            .await
        {
            Ok(Some(c)) if c.is_active() => Ok(c),
            Ok(Some(_)) => Err(self
                .client_auth_failed(tenant, client_id, "client_not_active", ctx)
                .await),
            Ok(None) => Err(self
                .client_auth_failed(tenant, client_id, "unknown_client", ctx)
                .await),
            Err(e) => Err(internal(&e)),
        }
    }

    /// トークンを発行してよい利用者か（両 grant 共通。認可コード交換とリフレッシュの双方が通る）。
    ///
    /// 利用者自身の状態に加えて、**所属元テナントが `ACTIVE`** であることも確かめる（ADR-0009 §8）。
    /// テナントの無効化はその組織の利用を止める操作であり、発行済みのリフレッシュトークンで
    /// 更新し続けられては止めたことにならない。無効化したテナント自身の `/{tenant_id}/token` は
    /// `TenantResolver` が 404 で止めるが、その利用者がゲストとして参加している**他テナントの**
    /// `/{tenant_id}/token` は生きているため、そこを塞ぐのはこの判定だけである。
    ///
    /// **キャッシュを通さず毎回 DB を見る。** ここは失効に相当する判定で、無効化を即座に効かせたい
    /// （テナント解決の TTL キャッシュに載せると、最大 TTL 分だけ更新が通ってしまう）。トークン
    /// 発行はもともとクライアント・コード／トークン・利用者・署名鍵を読むので、主キー 1 本の追加で済む。
    async fn load_active_user(
        &self,
        user_id: uuid::Uuid,
        _ctx: &RequestContext,
    ) -> Result<crate::domain::user::User, TokenError> {
        let user = match self.users.find_by_id(user_id).await {
            Ok(Some(u)) if u.is_active() => u,
            Ok(Some(_)) => {
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidGrant,
                    "user is not active",
                ))
            }
            Ok(None) => {
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidGrant,
                    "user no longer exists",
                ))
            }
            Err(e) => return Err(internal(&e)),
        };
        match self.tenants.find_by_id(user.tenant_id).await {
            Ok(Some(home)) if home.is_active() => Ok(user),
            // 不存在（テナントごと削除された）と `DISABLED` を区別しない。RP から見ればどちらも
            // 「この利用者ではもう発行できない」で、扱いは同じ。
            Ok(_) => Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "the user's home tenant is not active",
            )),
            Err(e) => Err(internal(&e)),
        }
    }

    async fn client_auth_failed(
        &self,
        tenant: TenantContext,
        client_id: &str,
        reason: &str,
        ctx: &RequestContext,
    ) -> TokenError {
        self.audit
            .record(
                AuditEventType::ClientAuthenticationFailed,
                AuditResult::Failure,
                Some(tenant.tenant_id()),
                None,
                Some(client_id),
                Some(reason),
                ctx,
            )
            .await;
        TokenError::new(
            OAuthErrorCode::InvalidClient,
            "client authentication failed",
        )
    }
}

/// client_id を Basic ヘッダ優先で解決する。
fn resolve_client_id(cmd: &TokenCommand) -> Result<String, TokenError> {
    // RFC 6749 §2.3.1: 1 リクエストで複数の認証方式を使ってはならない（G3）。client を引く前に弾く。
    cmd.credentials.ensure_single_method().map_err(|_| {
        TokenError::new(
            OAuthErrorCode::InvalidRequest,
            "client credentials must be presented with a single authentication method",
        )
    })?;
    match cmd.credentials.resolve_client_id() {
        Ok(client_id) => Ok(client_id),
        Err(ClientAuthFailure::ClientIdMismatch) => Err(TokenError::new(
            OAuthErrorCode::InvalidRequest,
            "client_id mismatch between Authorization header and body",
        )),
        Err(_) => Err(TokenError::new(
            OAuthErrorCode::InvalidClient,
            "client authentication is required",
        )),
    }
}

/// `client_credentials` の scope を決める（G4）。
///
/// - 要求あり: すべてがクライアントの登録 scope の部分集合であること（`/authorize` と同じ完全一致判定）。
/// - 要求なし: 登録 scope から**利用者前提の scope を除いた**集合を既定とする。`openid` は
///   「エンドユーザーの認証」を要求する scope、`profile` / `email` は利用者のクレームを指すもので、
///   利用者の居ないトークンに載せる意味がない。`offline_access` は Refresh Token の要求であり、
///   本 grant は資格情報を出し直せる（＝更新の必要がない）ため常に拒否する。
fn resolve_client_credentials_scopes(
    client: &Client,
    requested: Option<&str>,
) -> Result<Vec<String>, TokenError> {
    let user_bound = [
        Scope::OpenId.as_str(),
        Scope::Profile.as_str(),
        Scope::Email.as_str(),
    ];
    match requested.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            let scopes: Vec<String> = raw.split_whitespace().map(str::to_string).collect();
            if scopes.iter().any(|s| s == Scope::OfflineAccess.as_str()) {
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidScope,
                    "offline_access is not available for the client_credentials grant",
                ));
            }
            // 利用者前提の scope は、要求されても拒む。省略時は落としているのに明示要求だけ
            // 通すと、**利用者が居ないのに利用者のクレームを名乗るトークン**が出せてしまう。
            if scopes.iter().any(|s| user_bound.contains(&s.as_str())) {
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidScope,
                    "user-bound scopes are not available for the client_credentials grant",
                ));
            }
            if !client.allows_scopes(&scopes) {
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidScope,
                    "requested scope exceeds the scopes registered for this client",
                ));
            }
            Ok(scopes)
        }
        None => Ok(client
            .scopes
            .iter()
            .filter(|s| {
                s.as_str() != Scope::OfflineAccess.as_str() && !user_bound.contains(&s.as_str())
            })
            .cloned()
            .collect()),
    }
}

fn internal<E: std::fmt::Display>(e: &E) -> TokenError {
    tracing::error!(error = %e, "token endpoint internal error");
    TokenError {
        code: OAuthErrorCode::ServerError,
        description: "internal server error".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::tenant::TenantId;
    use crate::domain::values::{ClientStatus, ClientType, TokenEndpointAuthMethod};
    use chrono::TimeZone;

    fn client_with_scopes(scopes: &[&str]) -> Client {
        let now = chrono::Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap();
        Client {
            id: Uuid::from_u128(1),
            tenant_id: TenantId::from(Uuid::from_u128(2)),
            client_id: "svc".to_string(),
            client_secret_hash: None,
            client_type: ClientType::Confidential,
            client_status: ClientStatus::Active,
            app_name: "svc".to_string(),
            redirect_uris: vec![],
            grant_types: vec!["client_credentials".to_string()],
            response_types: vec!["code".to_string()],
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            jwks: None,
            post_logout_redirect_uris: vec![],
            frontchannel_logout_uri: None,
            backchannel_logout_uri: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// 登録できる scope は OIDC の 4 値だけ（`validate_scopes`）で、そのすべてが利用者前提か
    /// `offline_access` である。したがって **`client_credentials` のトークンは scope が空**になる。
    /// 業務上の権限はアプリが `sub`（= `client_id`）を見て判断する（ADR-0033）。
    #[test]
    fn client_credentials_tokens_carry_no_scope() {
        // システム用クライアントとして登録できる最小の姿。
        let client = client_with_scopes(&["openid"]);
        assert!(resolve_client_credentials_scopes(&client, None)
            .unwrap()
            .is_empty());

        // 利用者向けにも使うクライアントで登録され得る全 4 値でも同じ。
        let client = client_with_scopes(&["openid", "profile", "email", "offline_access"]);
        assert!(resolve_client_credentials_scopes(&client, None)
            .unwrap()
            .is_empty());
    }

    /// 未登録の scope は拒否する（`/authorize` と同じ完全一致判定）。
    ///
    /// 登録できる scope は OIDC の 4 値だけになった（ADR-0033）ので、この判定へ届くのは
    /// 制限より前に登録された行だけである。門番は残してあるため、その姿の行が来ても弾く。
    /// **利用者前提の scope で書くと 1 つ上の門番が先に弾き、この判定を通らない。**
    #[test]
    fn requested_scope_must_be_a_subset_of_the_registered_scopes() {
        // ADR-0033 より前に登録された姿（いまは登録できない）。
        let client = client_with_scopes(&["openid", "reports.read"]);
        let err = resolve_client_credentials_scopes(&client, Some("reports.write"))
            .expect_err("未登録 scope は拒否する");
        assert_eq!(err.code, OAuthErrorCode::InvalidScope);
    }

    /// 利用者前提の scope は、要求されても拒む。省略時は落としているのに明示要求だけ通すと、
    /// **利用者が居ないのに利用者のクレームを名乗るトークン**が出せてしまう。
    #[test]
    fn user_bound_scopes_are_rejected_even_when_registered() {
        let client = client_with_scopes(&["openid", "profile", "email"]);
        for requested in ["openid", "profile", "email", "openid profile"] {
            let err = resolve_client_credentials_scopes(&client, Some(requested))
                .expect_err("利用者前提の scope は拒否する");
            assert_eq!(
                err.code,
                OAuthErrorCode::InvalidScope,
                "requested={requested}"
            );
        }
    }

    /// `offline_access` は本 grant では常に拒否する（資格情報を出し直せるため更新の必要がない）。
    #[test]
    fn offline_access_is_rejected_even_when_registered() {
        let client = client_with_scopes(&["openid", "offline_access"]);
        let err = resolve_client_credentials_scopes(&client, Some("offline_access"))
            .expect_err("offline_access は拒否する");
        assert_eq!(err.code, OAuthErrorCode::InvalidScope);
    }

    /// 空文字・空白のみの scope は「省略」と同じに扱う（フォームの空欄で 400 にしない）。
    #[test]
    fn blank_scope_is_treated_as_omitted() {
        let client = client_with_scopes(&["openid"]);
        assert!(resolve_client_credentials_scopes(&client, Some("   "))
            .unwrap()
            .is_empty());
    }

    /// `sub_type` は `client_credentials` のトークンだけが持ち、省略時は利用者主体として読む
    /// （本クレーム導入前に発行したトークンとの互換）。
    #[test]
    fn subject_type_distinguishes_client_tokens_from_end_user_tokens() {
        let mut claims = AccessTokenClaims {
            iss: "https://idp.example.com/t".to_string(),
            sub: "svc".to_string(),
            aud: "https://idp.example.com/t/userinfo".to_string(),
            client_id: "svc".to_string(),
            scope: String::new(),
            exp: 0,
            iat: 0,
            jti: "j".to_string(),
            sub_type: Some(SUBJECT_TYPE_CLIENT.to_string()),
            perms: None,
        };
        assert!(claims.subject_is_client());
        claims.sub_type = None;
        assert!(!claims.subject_is_client());
    }
}
