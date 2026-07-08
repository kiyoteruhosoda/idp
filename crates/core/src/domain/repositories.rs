//! リポジトリトレイト（DIP 境界）。
//!
//! Application 層はこれらのトレイトにのみ依存し、Infrastructure 層（sqlx）が実装する。
//! トレイトオブジェクト（`Arc<dyn ...>`）として注入できるよう `#[async_trait]` を用いる。
//! メソッドは各フェーズで実装する際に必要に応じて拡張する。
#![allow(dead_code)]

use crate::domain::audit::{AuditEvent, AuditLogEntry, AuditLogFilter};
use crate::domain::auth_session::AuthSession;
use crate::domain::authorization_code::AuthorizationCode;
use crate::domain::client::Client;
use crate::domain::consent::ClientConsent;
use crate::domain::error::Result;
use crate::domain::refresh_token::RefreshToken;
use crate::domain::revoked_access_token::RevokedAccessToken;
use crate::domain::signing_key::SigningKey;
use crate::domain::sso_session::SsoSession;
use crate::domain::user::User;
use crate::domain::values::SigningKeyStatus;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create(&self, user: &User) -> Result<()>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>>;
    /// 外部公開識別子 `sub` で検索する（`/userinfo` で使用）。
    async fn find_by_sub(&self, sub: Uuid) -> Result<Option<User>>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>>;
    async fn find_by_username(&self, username: &str) -> Result<Option<User>>;
    /// ログイン失敗回数・ロック期限を更新する（ロックポリシー、設計仕様 §4.3）。
    async fn update_login_state(
        &self,
        id: Uuid,
        failed_login_count: i32,
        locked_until: Option<DateTime<Utc>>,
    ) -> Result<()>;
}

#[async_trait]
pub trait ClientRepository: Send + Sync {
    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<Client>>;
    /// クライアント（RP）を新規登録する（管理 API、設計仕様 §9.3）。`client_id` 重複は `Conflict`。
    async fn create(&self, client: &Client) -> Result<()>;
    /// 登録済みクライアントを新しい順に一覧する（管理画面 A3・A1）。
    async fn list(&self) -> Result<Vec<Client>>;
    /// 可変項目（app_name / redirect_uris / scopes / status / secret_hash 等）を更新する。
    /// 主キー `id` で対象を特定する。対象が無い場合は `NotFound`。
    async fn update(&self, client: &Client) -> Result<()>;
}

#[async_trait]
pub trait AuthSessionRepository: Send + Sync {
    async fn create(&self, session: &AuthSession) -> Result<()>;
    async fn find_by_id(&self, id: &str) -> Result<Option<AuthSession>>;
    /// 認証済みユーザーと `auth_time` を設定する（`/login` 成功時）。
    async fn set_authenticated_user(
        &self,
        id: &str,
        user_id: Uuid,
        auth_time: DateTime<Utc>,
    ) -> Result<()>;
    async fn delete(&self, id: &str) -> Result<()>;
}

#[async_trait]
pub trait SsoSessionRepository: Send + Sync {
    async fn create(&self, session: &SsoSession) -> Result<()>;
    async fn find_by_hash(&self, session_hash: &str) -> Result<Option<SsoSession>>;
    /// SSO 復元時に idle 期限を延長する（absolute は変更しない、設計仕様 §3.4）。
    async fn extend_idle(&self, session_hash: &str, idle_expires_at: DateTime<Utc>) -> Result<()>;
    async fn delete(&self, session_hash: &str) -> Result<()>;
    /// 指定ユーザーの全 SSO セッションを削除する（ユーザー単位の全セッション無効化、F5）。
    async fn delete_all_for_user(&self, user_id: Uuid) -> Result<()>;
}

#[async_trait]
pub trait AuthorizationCodeRepository: Send + Sync {
    async fn create(&self, code: &AuthorizationCode) -> Result<()>;
    /// 原子的に one-time 消費する。未使用かつ期限内なら `used_at` を設定して当該 code を返す。
    /// すでに使用済み・期限切れ・不存在なら `None`（呼び出し側で再利用検知として扱う）。
    async fn consume(
        &self,
        code_hash: &str,
        used_at: DateTime<Utc>,
    ) -> Result<Option<AuthorizationCode>>;
    /// ログアウト時にユーザーの未消費・期限内の全 code を即時失効させる（`used_at` を設定）。
    async fn revoke_all_active_for_user(&self, user_id: Uuid, now: DateTime<Utc>) -> Result<()>;
}

#[async_trait]
pub trait SigningKeyRepository: Send + Sync {
    async fn insert(&self, key: &SigningKey) -> Result<()>;
    /// 新規署名に使う ACTIVE 鍵を返す。
    async fn find_active(&self) -> Result<Option<SigningKey>>;
    /// JWKS 公開対象（ACTIVE + RETIRED で not_after が未来のもの）を返す。
    async fn list_published(&self) -> Result<Vec<SigningKey>>;
    async fn find_by_kid(&self, kid: &str) -> Result<Option<SigningKey>>;
    /// 全鍵を作成日時の降順で返す（管理画面用）。
    async fn list_all(&self) -> Result<Vec<SigningKey>>;
    /// ステータスを更新する（ACTIVE → RETIRED 等）。対象が無い場合は `NotFound`。
    async fn update_status(&self, kid: &str, status: SigningKeyStatus) -> Result<()>;
    /// 鍵を削除する。ACTIVE 鍵の削除は呼び出し側で禁止すること。
    async fn delete(&self, kid: &str) -> Result<()>;
}

#[async_trait]
pub trait AuditLogSink: Send + Sync {
    async fn record(&self, event: &AuditEvent) -> Result<()>;
}

/// `audit_log` の読み取り（状況確認画面 A3）。書き込み（`AuditLogSink`）とは関心を分ける。
#[async_trait]
pub trait AuditLogQuery: Send + Sync {
    /// 条件に一致する監査ログを新しい順（`occurred_at` 降順、同時刻は `id` 降順）に返す。
    async fn search(&self, filter: &AuditLogFilter) -> Result<Vec<AuditLogEntry>>;

    /// クライアント別の**最終利用時刻**（成功したトークン発行・認可コード発行の最新 `occurred_at`）を返す。
    /// クライアント状況一覧（A3）が利用する。利用実績の無いクライアントは含まれない。
    async fn last_used_per_client(&self) -> Result<Vec<(String, DateTime<Utc>)>>;
}

/// 利用者が保有する権限コード（ADR-0006）の参照・付与・剥奪（DIP 境界）。
///
/// OIDC scope（`ClientRepository` 側の関心）とは別軸。保護ユースケースは本トレイト越しに
/// 「利用者が必要権限を保有するか」を判定する。付与/剥奪は管理コンソール（A2）が用いる。
#[async_trait]
pub trait UserPermissionRepository: Send + Sync {
    /// 付与可能な権限コードの一覧（`permissions` マスタ）を昇順で返す。
    /// 管理コンソール（A2）の付与フォームで選択肢を提示するために使う。
    async fn list_available_codes(&self) -> Result<Vec<String>>;
    /// 利用者が保有する権限コード一覧を返す（順序は不定）。
    async fn list_codes_for_user(&self, user_id: Uuid) -> Result<Vec<String>>;
    /// 利用者が指定の権限コードを保有するか。
    async fn has_permission(&self, user_id: Uuid, code: &str) -> Result<bool>;
    /// 権限を付与する（冪等: 既存付与は何もしない）。`code` は `permissions` マスタに存在すること。
    async fn grant(&self, user_id: Uuid, code: &str, granted_at: DateTime<Utc>) -> Result<()>;
    /// 権限を剥奪する（不存在でもエラーにしない）。
    async fn revoke(&self, user_id: Uuid, code: &str) -> Result<()>;
}

/// Refresh Token の永続化（設計仕様 §9.1）。DB には SHA-256 hash を保存する。
#[async_trait]
pub trait RefreshTokenRepository: Send + Sync {
    /// 新規 Refresh Token を保存する。
    async fn create(&self, token: &RefreshToken) -> Result<()>;
    /// hash で検索する。不存在は `None`。
    async fn find_by_hash(&self, token_hash: &str) -> Result<Option<RefreshToken>>;
    /// 指定 hash のトークンを失効させる（`revoked_at` を設定）。
    /// 不存在・既失効でもエラーにしない（冪等）。
    async fn revoke(&self, token_hash: &str, revoked_at: DateTime<Utc>) -> Result<()>;
    /// `parent_hash` でチェーンを検索し、存在する（未失効・失効問わず）場合は `true`。
    /// reuse detection で同一 parent から二重発行が起きていないかを確認するために使う。
    async fn exists_by_parent_hash(&self, parent_hash: &str) -> Result<bool>;
    /// 指定ユーザーの全 Refresh Token を失効させる（ユーザー単位の全セッション無効化、F5）。
    async fn revoke_all_for_user(&self, user_id: Uuid, revoked_at: DateTime<Utc>) -> Result<()>;
}

/// ユーザーがクライアントに付与した同意済み scope の永続化（F3: Consent）。
#[async_trait]
pub trait ClientConsentRepository: Send + Sync {
    /// `(user_id, client_id)` の同意レコードを返す。存在しなければ `None`。
    async fn find(&self, user_id: Uuid, client_id: &str) -> Result<Option<ClientConsent>>;
    /// 同意レコードを UPSERT する（scope が変わった場合は上書き）。
    async fn upsert(&self, consent: &ClientConsent) -> Result<()>;
    /// 同意を取り消す（存在しなければ冪等に何もしない）。
    async fn revoke(&self, user_id: Uuid, client_id: &str) -> Result<()>;
    /// ユーザーの全同意レコードを返す（同意取り消し画面・管理用）。
    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<ClientConsent>>;
}

/// Access Token の jti 失効リスト（F5: Token 管理）。
/// JWT は自己完結型のため、jti を本テーブルで管理することで即時失効を実現する。
#[async_trait]
pub trait RevokedAccessTokenRepository: Send + Sync {
    /// jti を失効リストに追加する（冪等）。
    async fn revoke(
        &self,
        token: &RevokedAccessToken,
    ) -> Result<()>;
    /// 指定 jti が失効リストに存在するか。
    async fn is_revoked(&self, jti: &str) -> Result<bool>;
}
