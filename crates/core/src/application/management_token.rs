//! 管理 API のアクセストークン（ADR-0037）。
//!
//! この IdP 自身を操作する API（`/{tenant_id}/admin/*`）の認可は、**主体が人か機械かに関わらず
//! アクセストークン 1 本に寄せる**。管理コンソール（web）は SSO セッションを本サービスで管理
//! トークンへ交換し、システム用クライアントは `client_credentials` に `resource` を添えて受け取る。
//!
//! ## なぜ Cookie 転送をやめるのか
//!
//! 従来 `/admin/*` は web が転送した SSO セッション Cookie だけを資格情報にしていた。機械から
//! 呼ぶ手段が無く、かつ Cookie は ambient（ブラウザが自動で付ける）なので api 側に CSRF の
//! 心配（オリジン検証）が残っていた。Bearer は ambient ではないため、api の管理面から CSRF の
//! 論点そのものが消える。ブラウザ経路の CSRF は web が同期トークンで閉じて扱う（`web::csrf`）。
//!
//! ## トークンが持つ権限と、リクエスト毎に確かめること
//!
//! **権限の出所はトークン**（`perms` クレーム）である。リクエスト毎に権限を引き直すと、
//! トークンに権限を載せる意味が無くなる。ただし**主体がまだ使えるか**（利用者が有効か・
//! クライアントが有効か）だけは毎回確かめる。無効化した管理者や停止したシステム用クライアントが
//! トークンの残存期間だけ操作を続けられる、という状態を作らないためである。
//!
//! `perms` は `aud` が管理 API のトークンにしか載らない。他のリソースサーバ向けトークンへ
//! 権限コードが流れ込まないという ADR-0033 の決定は、この `aud` 固定で保たれる。

use crate::application::admin_access::AdminAccessService;
use crate::application::key_service::KeyService;
use crate::application::token::{management_audience, AccessTokenClaims, SUBJECT_TYPE_CLIENT};
use crate::domain::admin_actor::AdminActor;
use crate::domain::clock::Clock;
use crate::domain::issuer::tenant_issuer;
use crate::domain::jwt;
use crate::domain::permission;
use crate::domain::repositories::{
    ClientRepository, RevokedAccessTokenRepository, SigningKeyRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use chrono::Duration;
use jsonwebtoken::{Algorithm, Validation};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use uuid::Uuid;

/// 管理 API へのアクセス判定結果。Presentation へは可否のみを渡す（内部理由は漏らさない）。
#[derive(Debug, PartialEq, Eq)]
pub enum ManagementAccess {
    /// 認可済み。要求された管理操作を行ってよい。
    Granted(AuthorizedPrincipal),
    /// 有効な管理トークンが無い（未提示・改竄・期限切れ・失効済み）→ 401 相当。
    Unauthenticated,
    /// トークンは有効だが必要権限を保有しない → 403 相当。
    Forbidden,
}

/// 認可された管理主体（Presentation ハンドラへ注入される最小限の身元）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedPrincipal {
    /// 監査ログへ残す実行主体（利用者 or クライアント）。
    pub actor: AdminActor,
    /// 表示名（管理コンソールのヘッダ表示に使う。クライアント主体では `app_name`）。
    pub name: Option<String>,
    /// ログイン識別子（クライアント主体では `None`）。
    pub preferred_username: Option<String>,
}

/// SSO セッションから発行した管理トークン。
pub struct IssuedManagementToken {
    pub access_token: String,
    pub expires_in: u64,
    /// 発行時点で主体が保有していた権限コード（コンソールが画面の出し分けに使う）。
    pub permission_codes: Vec<String>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
}

/// 管理トークンの発行に失敗した理由。
#[derive(Debug, PartialEq, Eq)]
pub enum ManagementTokenError {
    /// 有効な SSO セッションが無い（未ログイン・期限切れ・利用者が無効）→ 401 相当。
    Unauthenticated,
    Internal(String),
}

pub struct ManagementTokenService {
    admin_access: Arc<AdminAccessService>,
    keys: Arc<KeyService>,
    signing_keys: Arc<dyn SigningKeyRepository>,
    users: Arc<dyn UserRepository>,
    clients: Arc<dyn ClientRepository>,
    revoked_access_tokens: Arc<dyn RevokedAccessTokenRepository>,
    clock: Arc<dyn Clock>,
    base_issuer: String,
    ttl: StdDuration,
    clock_skew: Duration,
}

impl ManagementTokenService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admin_access: Arc<AdminAccessService>,
        keys: Arc<KeyService>,
        signing_keys: Arc<dyn SigningKeyRepository>,
        users: Arc<dyn UserRepository>,
        clients: Arc<dyn ClientRepository>,
        revoked_access_tokens: Arc<dyn RevokedAccessTokenRepository>,
        clock: Arc<dyn Clock>,
        base_issuer: String,
        ttl: StdDuration,
        clock_skew: StdDuration,
    ) -> Self {
        Self {
            admin_access,
            keys,
            signing_keys,
            users,
            clients,
            revoked_access_tokens,
            clock,
            base_issuer,
            ttl,
            clock_skew: Duration::from_std(clock_skew).expect("clock skew out of range"),
        }
    }

    /// SSO セッションを管理トークンへ交換する（管理コンソール経路。`POST /internal/admin/token`）。
    ///
    /// セッションが無効なら `Unauthenticated`。セッションが有効なら、保有権限が 0 件でも
    /// **トークンは発行する**。「ログインはしているが権限が無い」を 403 として表現できるように
    /// するためで、ここで 403 に倒すと web はログイン画面へ戻す判断ができなくなる。
    pub async fn issue_for_session(
        &self,
        tenant: TenantContext,
        sso_session_id: Option<&str>,
    ) -> Result<IssuedManagementToken, ManagementTokenError> {
        let grant = self
            .admin_access
            .resolve_session_grant(tenant, sso_session_id)
            .await
            .ok_or(ManagementTokenError::Unauthenticated)?;

        let access_token = self
            .sign(
                tenant,
                &grant.user_id.to_string(),
                None,
                &grant.permission_codes,
            )
            .await?;

        Ok(IssuedManagementToken {
            access_token,
            expires_in: self.ttl.as_secs(),
            permission_codes: grant.permission_codes,
            name: grant.name,
            preferred_username: grant.preferred_username,
        })
    }

    /// 管理トークンを検証し、要求権限コードを満たすかを判定する（`RequirePerms` から呼ぶ）。
    ///
    /// 検証は 署名 → `typ` → `iss` → `aud` → `exp` → 失効（jti）→ 主体の有効性 → 権限 の順。
    /// 失敗理由は 401 / 403 の 2 値へ畳んで返す（どの段で落ちたかは呼び出し側へ渡さない）。
    pub async fn authorize(
        &self,
        tenant: TenantContext,
        bearer_token: Option<&str>,
        required_permission: &str,
    ) -> ManagementAccess {
        let Some(token) = bearer_token.filter(|t| !t.is_empty()) else {
            return ManagementAccess::Unauthenticated;
        };
        let claims = match self.verify(tenant, token).await {
            Ok(claims) => claims,
            Err(reason) => {
                tracing::debug!(reason, "management token rejected");
                return ManagementAccess::Unauthenticated;
            }
        };

        // 主体がまだ使えるか（無効化された管理者・停止したクライアントを締め出す）。
        let principal = match self.resolve_principal(tenant, &claims).await {
            Some(principal) => principal,
            None => return ManagementAccess::Unauthenticated,
        };

        let held: Vec<&str> = claims
            .perms
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .collect();
        if permission::satisfies(&held, required_permission) {
            ManagementAccess::Granted(principal)
        } else {
            ManagementAccess::Forbidden
        }
    }

    /// 管理トークンへ署名する。`aud` は要求テナントの管理 API に固定する。
    async fn sign(
        &self,
        tenant: TenantContext,
        subject: &str,
        client_id: Option<&str>,
        permission_codes: &[String],
    ) -> Result<String, ManagementTokenError> {
        let now = self.clock.now();
        let iat = now.timestamp();
        let issuer = tenant_issuer(&self.base_issuer, tenant.tenant_id());
        let claims = AccessTokenClaims {
            iss: issuer.clone(),
            sub: subject.to_string(),
            aud: management_audience(&issuer),
            // 利用者主体の管理トークンはクライアント経由で得たものではないため、`client_id` は
            // 主体自身（クライアント主体のとき）だけが埋まる。
            client_id: client_id.unwrap_or_default().to_string(),
            scope: String::new(),
            exp: iat + self.ttl.as_secs() as i64,
            iat,
            jti: Uuid::new_v4().to_string(),
            sub_type: client_id.map(|_| SUBJECT_TYPE_CLIENT.to_string()),
            perms: Some(permission_codes.join(" ")),
        };
        let key = self
            .keys
            .active_signing_key()
            .await
            .map_err(|e| ManagementTokenError::Internal(e.to_string()))?;
        jwt::sign(
            &key.private_pem,
            &key.kid,
            "at+jwt",
            &key.algorithm,
            &claims,
        )
        .map_err(|e| ManagementTokenError::Internal(e.to_string()))
    }

    /// 署名・`typ`・`iss`・`aud`・`exp`・失効を検証してクレームを返す。
    async fn verify(
        &self,
        tenant: TenantContext,
        token: &str,
    ) -> Result<AccessTokenClaims, &'static str> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| "malformed token")?;
        if header.typ.as_deref() != Some("at+jwt") {
            return Err("token typ must be `at+jwt`");
        }
        let kid = header.kid.ok_or("token has no kid")?;

        let key = self
            .signing_keys
            .find_by_kid(&kid)
            .await
            .map_err(|_| "signing key lookup failed")?
            .ok_or("unknown signing key")?;
        let decoding_key = jwt::decoding_key_from_public_pem(&key.public_key)
            .map_err(|_| "unusable public key")?;

        // exp / aud は Clock トレイト経由の時刻で自前検証する（テストで時刻固定するため）。
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        let data = jsonwebtoken::decode::<AccessTokenClaims>(token, &decoding_key, &validation)
            .map_err(|_| "signature verification failed")?;
        let claims = data.claims;

        let expected_issuer = tenant_issuer(&self.base_issuer, tenant.tenant_id());
        if claims.iss != expected_issuer {
            return Err("issuer mismatch");
        }
        // `aud` が管理 API であることが要。`/userinfo` 向けトークンを管理 API へ持ち込ませない。
        if claims.aud != management_audience(&expected_issuer) {
            return Err("audience mismatch");
        }
        let now = self.clock.now().timestamp();
        if claims.exp + self.clock_skew.num_seconds() <= now {
            return Err("token expired");
        }
        if !claims.jti.is_empty() {
            match self.revoked_access_tokens.is_revoked(&claims.jti).await {
                Ok(true) => return Err("token has been revoked"),
                Ok(false) => {}
                Err(_) => return Err("revocation lookup failed"),
            }
        }
        Ok(claims)
    }

    /// トークンの `sub` から主体を解決し、まだ使える状態かを確かめる（fail-closed）。
    async fn resolve_principal(
        &self,
        tenant: TenantContext,
        claims: &AccessTokenClaims,
    ) -> Option<AuthorizedPrincipal> {
        if claims.subject_is_client() {
            let client = match self
                .clients
                .find_by_client_id(tenant.tenant_id(), &claims.sub)
                .await
            {
                Ok(Some(client)) if client.is_active() => client,
                Ok(_) => return None,
                Err(e) => {
                    tracing::error!(error = %e, "failed to load client for management token");
                    return None;
                }
            };
            return Some(AuthorizedPrincipal {
                actor: AdminActor::Client {
                    id: client.id,
                    client_id: client.client_id.clone(),
                },
                name: Some(client.app_name),
                preferred_username: None,
            });
        }

        let user_id = Uuid::parse_str(&claims.sub).ok()?;
        match self.users.find_by_id(user_id).await {
            Ok(Some(user)) if user.is_active() => Some(AuthorizedPrincipal {
                actor: AdminActor::User(user.id),
                name: user.name,
                preferred_username: user.preferred_username,
            }),
            Ok(_) => None,
            Err(e) => {
                tracing::error!(error = %e, "failed to load user for management token");
                None
            }
        }
    }
}
