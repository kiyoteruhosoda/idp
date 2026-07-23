//! リポジトリトレイト（DIP 境界）。
//!
//! Application 層はこれらのトレイトにのみ依存し、Infrastructure 層（sqlx）が実装する。
//! トレイトオブジェクト（`Arc<dyn ...>`）として注入できるよう `#[async_trait]` を用いる。
//! メソッドは各フェーズで実装する際に必要に応じて拡張する。
//!
//! # テナント分離（ADR-0009 §8）
//!
//! MariaDB に RLS はなく、アプリ層が唯一の分離防御線となる。テナントスコープのテーブルを
//! 参照・検索するメソッドは `tenant_id: TenantId` を受け取り、実装は必ず WHERE 句へ含める。
//! 次のものは意図的に tenant_id を取らない:
//!
//! - **グローバル一意キーによる本人解決**（`users.id` / `users.sub`）: ゲスト参加（§3）では
//!   フローのテナント ≠ 所属元テナントのため、テナント境界はメンバーシップ判定・所属元照合で
//!   強制する（ユースケース側の責務）。
//! - **SSO セッション**: ホスト単位で共有する設計（§8）。境界はメンバーシップ検証で強制する。
//! - **ユーザー単位のセキュリティ操作**（全セッション失効・全 code/refresh token 失効）:
//!   本人のユーザー状態への操作であり、テナントを跨いで全失効させる方が安全側。
//! - **テナント列を持たないテーブル**（署名鍵・jti 失効リスト・TOTP・WebAuthn・チャレンジ）。
#![allow(dead_code)]

use crate::domain::audit::{AuditEvent, AuditLogEntry, AuditLogFilter};
use crate::domain::auth_session::AuthSession;
use crate::domain::authorization_code::AuthorizationCode;
use crate::domain::client::Client;
use crate::domain::consent::ClientConsent;
use crate::domain::email_verification::EmailVerificationToken;
use crate::domain::error::Result;
use crate::domain::passkey_challenge::PasskeyChallenge;
use crate::domain::password_reset::PasswordResetToken;
use crate::domain::refresh_token::RefreshToken;
use crate::domain::revoked_access_token::RevokedAccessToken;
use crate::domain::saml_service_provider::SamlServiceProvider;
use crate::domain::signing_key::SigningKey;
use crate::domain::sso_session::SsoSession;
use crate::domain::system_setting::SystemSetting;
use crate::domain::tenant::{Tenant, TenantId};
use crate::domain::tenant_membership::TenantMembership;
use crate::domain::totp_secret::TotpSecret;
use crate::domain::user::User;
use crate::domain::values::{SigningKeyStatus, UserStatus};
use crate::domain::webauthn_credential::WebAuthnCredential;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// テナント（ADR-0009 §1）の永続化。テナントは互いに独立した管理境界であり、`parent_tenant_id`
/// は系譜であって権限境界ではない。
#[async_trait]
pub trait TenantRepository: Send + Sync {
    async fn create(&self, tenant: &Tenant) -> Result<()>;
    async fn find_by_id(&self, id: TenantId) -> Result<Option<Tenant>>;
    /// `parent_tenant_id IS NULL` の唯一の行（root）を返す。
    async fn find_root(&self) -> Result<Option<Tenant>>;
    /// 指定テナントの直下の子テナントを一覧する（`/{tenant_id}/admin/tenants`。ADR-0009 §6）。
    async fn list_children(&self, parent_id: TenantId) -> Result<Vec<Tenant>>;
    /// 表示名・状態を更新する（`parent_tenant_id` の付け替えは禁止。呼び出し側が保証する）。
    async fn update(&self, tenant: &Tenant) -> Result<()>;
    /// テナントを削除する。「配下に子テナントが無く、当該テナント自身にユーザー/クライアントが
    /// 存在しない」ことは呼び出し側が事前検証する（DB も `ON DELETE RESTRICT` で保護する）。
    async fn delete(&self, id: TenantId) -> Result<()>;
}

/// テナント開通（ADR-0009 §5）のトランザクション境界（unit of work）。
///
/// テナント作成は「テナント行・初期管理者ユーザー・HOME メンバーシップ・`idp.tenant.admin` 付与」の
/// 4 行が揃って初めて意味を持つ（どれか欠けると管理者のいないテナント＝孤立テナントが残る）。
/// 本ポートはこの集約を**単一トランザクションで**永続化し、途中失敗時は全体をロールバックする（REF2）。
/// ドメインオブジェクトの構築・検証は Application 層の責務で、実装は永続化のみを担う。
#[async_trait]
pub trait TenantProvisioningRepository: Send + Sync {
    /// テナント・初期管理者・HOME メンバーシップ・権限付与を原子的に永続化する。
    /// 一意制約違反（email / preferred_username / root 重複）は `Conflict`、
    /// `admin_permission_code` が `permissions` マスタに無い場合は `InvalidValue` を返す。
    async fn provision(
        &self,
        tenant: &Tenant,
        admin: &User,
        admin_membership: &TenantMembership,
        admin_permission_code: &str,
        granted_at: DateTime<Utc>,
    ) -> Result<()>;
}

/// テナントメンバーシップ（招待・ゲスト参加。ADR-0009 §3）の永続化。
#[async_trait]
pub trait TenantMembershipRepository: Send + Sync {
    /// メンバーシップを作成する（HOME はユーザー作成時、GUEST は招待作成時）。
    async fn create(&self, membership: &TenantMembership) -> Result<()>;
    async fn find(&self, tenant_id: TenantId, user_id: Uuid) -> Result<Option<TenantMembership>>;
    /// 指定テナントのメンバー一覧（HOME / GUEST）を返す（`/{tenant_id}/admin/members`）。
    async fn list_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<TenantMembership>>;
    /// ユーザーが指定テナントで `ACTIVE` なメンバーシップ（HOME または GUEST）を持つか
    /// （OIDC フローのメンバーシップ判定。ADR-0009 §8）。
    async fn is_active_member(&self, tenant_id: TenantId, user_id: Uuid) -> Result<bool>;
    /// 招待トークンのハッシュで `INVITED` 中の行を検索する（承諾エンドポイント用）。
    async fn find_by_invitation_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<TenantMembership>>;
    /// 招待を承諾し、`ACTIVE` へ遷移させる（トークン関連カラムは呼び出し側でクリアする）。
    async fn activate(&self, tenant_id: TenantId, user_id: Uuid) -> Result<()>;
    /// ゲストメンバーシップを解除する（HOME の解除は呼び出し側が禁止する）。
    async fn delete(&self, tenant_id: TenantId, user_id: Uuid) -> Result<()>;
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    /// ユーザーを作成する（`user.tenant_id` = 所属元テナント）。HOME メンバーシップの同時作成は
    /// ユースケース側の責務（ADR-0009 §3）。
    async fn create(&self, user: &User) -> Result<()>;
    /// グローバル一意の内部 ID で解決する（テナント境界は呼び出し側が所属元照合・メンバーシップ
    /// 判定で強制する。モジュールコメント参照）。
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>>;
    /// 外部公開識別子 `sub` で検索する（`/userinfo` で使用。グローバル一意）。
    async fn find_by_sub(&self, sub: Uuid) -> Result<Option<User>>;
    /// 所属元が `tenant_id` のユーザーを email で検索する（一意キーは `(tenant_id, email)`。
    /// 認証は所属元テナント限定 = ログイン画面のユーザー検索はこれを使う。ADR-0009 §8）。
    async fn find_by_email(&self, tenant_id: TenantId, email: &str) -> Result<Option<User>>;
    /// 所属元が `tenant_id` のユーザーを preferred_username で検索する。
    async fn find_by_username(&self, tenant_id: TenantId, username: &str) -> Result<Option<User>>;
    /// 複数の内部 ID で一括取得する（N+1 回避。`list_members` 等で使用）。
    /// 見つかったものだけを返す（欠落は無視）。順序は保証しない。
    async fn find_by_ids(&self, ids: &[Uuid]) -> Result<Vec<User>> {
        let mut result = Vec::with_capacity(ids.len());
        for &id in ids {
            if let Some(u) = self.find_by_id(id).await? {
                result.push(u);
            }
        }
        Ok(result)
    }
    /// ログイン失敗回数・ロック期限を更新する（ロックポリシー、設計仕様 §4.3）。
    async fn update_login_state(
        &self,
        id: Uuid,
        failed_login_count: i32,
        locked_until: Option<DateTime<Utc>>,
    ) -> Result<()>;
    /// パスワードハッシュを更新し、`must_change_password` を解除する（パスワード変更、ADR-0009 §5）。
    async fn update_password(&self, id: Uuid, password_hash: &str) -> Result<()>;
    /// パスワードハッシュを更新し、`must_change_password` を**設定**する（管理者による再発行。
    /// 次回ログインで本人に変更させる。ADR-0009 §5）。
    async fn reset_password_forced(&self, id: Uuid, password_hash: &str) -> Result<()>;
    /// 利用者の状態（ACTIVE / DISABLED / LOCKED）を更新する（管理者による有効化・無効化）。
    async fn update_status(&self, id: Uuid, status: UserStatus) -> Result<()>;
    /// 利用者を削除する（管理者による削除。関連行は DB の FK CASCADE / SET NULL で後始末される）。
    async fn delete(&self, id: Uuid) -> Result<()>;
    /// メール検証済みフラグを立てる（自己登録アカウントの確認リンク消費時。SEC6b）。
    async fn mark_email_verified(&self, id: Uuid) -> Result<()>;
    /// 表示言語設定を更新する（MT20。`None` で設定解除）。
    async fn update_language(&self, id: Uuid, language: Option<&str>) -> Result<()>;
}

#[async_trait]
pub trait ClientRepository: Send + Sync {
    /// `client_id` はテナント内一意のため `(tenant_id, client_id)` で検索する（ADR-0009 §2）。
    async fn find_by_client_id(
        &self,
        tenant_id: TenantId,
        client_id: &str,
    ) -> Result<Option<Client>>;
    /// クライアント（RP）を新規登録する（管理 API、設計仕様 §9.3）。`client.tenant_id` の
    /// テナントへ登録し、テナント内の `client_id` 重複は `Conflict`。
    async fn create(&self, client: &Client) -> Result<()>;
    /// 指定テナントの登録済みクライアントを新しい順に一覧する（管理画面 A3・A1）。
    async fn list(&self, tenant_id: TenantId) -> Result<Vec<Client>>;
    /// 可変項目（app_name / redirect_uris / scopes / status / secret_hash 等）を更新する。
    /// `(id, tenant_id)` で対象を特定する（他テナントの行は更新できない）。対象が無い場合は `NotFound`。
    async fn update(&self, client: &Client) -> Result<()>;
}

/// SAML SP（クライアント）登録の永続化。テナント境界は `tenant_id` で強制する。
#[async_trait]
pub trait SamlServiceProviderRepository: Send + Sync {
    async fn create(&self, provider: &SamlServiceProvider) -> Result<()>;
    async fn list_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<SamlServiceProvider>>;
    /// テナント境界内で id 解決する（他テナントの id を持ち込んでも解決させない）。
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> Result<Option<SamlServiceProvider>>;
    /// 既存 SP を更新する（同一テナント・id のレコードのみ。entity_id 重複は `Conflict`）。
    async fn update(&self, provider: &SamlServiceProvider) -> Result<()>;
    /// テナント境界内で SP を削除する。削除できた場合 `true`、対象が無ければ `false`。
    async fn delete(&self, tenant_id: TenantId, id: Uuid) -> Result<bool>;
}

#[async_trait]
pub trait AuthSessionRepository: Send + Sync {
    async fn create(&self, session: &AuthSession) -> Result<()>;
    /// フローを開始したテナントの auth session のみ返す（他テナントの session id を
    /// 持ち込んでも解決させない）。
    async fn find_by_id(&self, tenant_id: TenantId, id: &str) -> Result<Option<AuthSession>>;
    /// 認証済みユーザーと `auth_time` を設定する（`/login` 成功時）。
    async fn set_authenticated_user(
        &self,
        id: &str,
        user_id: Uuid,
        auth_time: DateTime<Utc>,
    ) -> Result<()>;
    /// パスワード検証成功後に MFA pending 状態を記録する（`password_verified_at` を設定）。
    async fn set_password_verified(
        &self,
        id: &str,
        user_id: Uuid,
        verified_at: DateTime<Utc>,
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
    /// 原子的に one-time 消費する。発行テナントが一致し、未使用かつ期限内なら `used_at` を
    /// 設定して当該 code を返す。すでに使用済み・期限切れ・不存在・他テナント発行なら `None`
    /// （呼び出し側で再利用検知として扱う）。
    async fn consume(
        &self,
        tenant_id: TenantId,
        code_hash: &str,
        used_at: DateTime<Utc>,
    ) -> Result<Option<AuthorizationCode>>;
    /// ログアウト時にユーザーの未消費・期限内の全 code を即時失効させる（`used_at` を設定）。
    async fn revoke_all_active_for_user(&self, user_id: Uuid, now: DateTime<Utc>) -> Result<()>;
}

/// パスワードリセットトークン（MT18）の永続化。DB には SHA-256 hash のみ保存する。
/// ユーザー単位のセキュリティ操作のため tenant_id は取らない（モジュールコメント参照。
/// テナント境界はユースケース側が `users.tenant_id` 照合で強制する）。
#[async_trait]
pub trait PasswordResetTokenRepository: Send + Sync {
    async fn create(&self, token: &PasswordResetToken) -> Result<()>;
    /// 原子的に one-time 消費する。未使用かつ期限内なら `used_at` を設定して当該行を返す。
    /// 使用済み・期限切れ・不存在は `None`。
    async fn consume(
        &self,
        token_hash: &str,
        used_at: DateTime<Utc>,
    ) -> Result<Option<PasswordResetToken>>;
    /// 当該ユーザーの未使用トークンをすべて失効させる（`used_at` を設定。再発行時の置き換えに使う）。
    async fn invalidate_all_for_user(&self, user_id: Uuid, now: DateTime<Utc>) -> Result<()>;
}

/// メール検証トークン（SEC6b）の永続化。DB には SHA-256 hash のみ保存する。
/// `PasswordResetTokenRepository` と同じ one-time パターン（tenant_id は取らない。テナント境界は
/// ユースケース側が `users.tenant_id` 照合で強制する）。
#[async_trait]
pub trait EmailVerificationTokenRepository: Send + Sync {
    async fn create(&self, token: &EmailVerificationToken) -> Result<()>;
    /// 原子的に one-time 消費する。未使用かつ期限内なら `used_at` を設定して当該行を返す。
    /// 使用済み・期限切れ・不存在は `None`。
    async fn consume(
        &self,
        token_hash: &str,
        used_at: DateTime<Utc>,
    ) -> Result<Option<EmailVerificationToken>>;
    /// 当該ユーザーの未使用トークンをすべて失効させる（再送時の置き換えに使う）。
    async fn invalidate_all_for_user(&self, user_id: Uuid, now: DateTime<Utc>) -> Result<()>;
}

#[async_trait]
pub trait SigningKeyRepository: Send + Sync {
    async fn insert(&self, key: &SigningKey) -> Result<()>;
    /// **ACTIVE 鍵が 1 本も無い場合に限り** `key` を挿入する（ブートストラップ専用の排他挿入）。
    /// 挿入したら `true`、既に ACTIVE 鍵が存在して何もしなかったら `false` を返す。
    /// 「存在確認 → 挿入」を排他区間で行い、複数インスタンスの同時起動でも ACTIVE 鍵が
    /// 重複生成されないことを実装が保証する（SEC5）。
    async fn insert_if_no_active(&self, key: &SigningKey) -> Result<bool>;
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
    /// テナント越しの閲覧を防ぐため、参照系の呼び出しは `filter.tenant_id` を必ず設定する。
    async fn search(&self, filter: &AuditLogFilter) -> Result<Vec<AuditLogEntry>>;

    /// 指定テナントのクライアント別の**最終利用時刻**（成功したトークン発行・認可コード発行の
    /// 最新 `occurred_at`）を返す。クライアント状況一覧（A3）が利用する。利用実績の無い
    /// クライアントは含まれない。
    async fn last_used_per_client(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<(String, DateTime<Utc>)>>;
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
    /// 利用者が `tenant_id` を scope として保有する権限コード一覧を返す（順序は不定）。
    async fn list_codes_for_user(&self, tenant_id: TenantId, user_id: Uuid) -> Result<Vec<String>>;
    /// 利用者が指定の権限コードを `tenant_id` を scope として保有するか（完全一致判定。ADR-0009 §4）。
    async fn has_permission(&self, tenant_id: TenantId, user_id: Uuid, code: &str) -> Result<bool>;
    /// 指定コードのうち**いずれか 1 つ**を保有するか（OR 判定）。
    ///
    /// 認可ホットパスで「要求権限 or idp.system.admin」の判定を 1 往復に束ねるために使う（REF3）。
    /// デフォルト実装は `has_permission` を順に呼ぶ。DB 実装は単一 `IN` クエリで上書きする。
    async fn has_any_permission(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        codes: &[&str],
    ) -> Result<bool> {
        for &code in codes {
            if self.has_permission(tenant_id, user_id, code).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// `tenant_id` を scope として権限を付与する（冪等: 既存付与は何もしない）。
    /// `code` は `permissions` マスタに存在すること。
    async fn grant(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        code: &str,
        granted_at: DateTime<Utc>,
    ) -> Result<()>;
    /// `tenant_id` を scope とする権限を剥奪する（不存在でもエラーにしない）。
    async fn revoke(&self, tenant_id: TenantId, user_id: Uuid, code: &str) -> Result<()>;
    /// `tenant_id` を scope とする当該利用者の**全**権限行を一括で剥奪し、剥奪したコード一覧を返す
    /// （不保有なら空。ゲスト追放時の後始末に使う。ADR-0009 §3）。読み取りと削除は原子的に行う。
    async fn revoke_all_for_user_in_tenant(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> Result<Vec<String>>;
}

/// Refresh Token の永続化（設計仕様 §9.1）。DB には SHA-256 hash を保存する。
#[async_trait]
pub trait RefreshTokenRepository: Send + Sync {
    /// 新規 Refresh Token を保存する（`token.tenant_id` = 発行テナント）。
    async fn create(&self, token: &RefreshToken) -> Result<()>;
    /// 発行テナントが一致する行を hash で検索する。不存在・他テナント発行は `None`
    /// （A テナント発行トークンの B テナントへの流用を防ぐ。ADR-0009 §6）。
    async fn find_by_hash(
        &self,
        tenant_id: TenantId,
        token_hash: &str,
    ) -> Result<Option<RefreshToken>>;
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
    /// `(user_id, tenant_id, client_id)` の同意レコードを返す。存在しなければ `None`。
    async fn find(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        client_id: &str,
    ) -> Result<Option<ClientConsent>>;
    /// 同意レコードを UPSERT する（scope が変わった場合は上書き）。
    async fn upsert(&self, consent: &ClientConsent) -> Result<()>;
    /// 同意を取り消す（存在しなければ冪等に何もしない）。
    async fn revoke(&self, tenant_id: TenantId, user_id: Uuid, client_id: &str) -> Result<()>;
    /// 指定テナントにおけるユーザーの全同意レコードを返す（同意取り消し画面・管理用）。
    async fn list_for_user(&self, tenant_id: TenantId, user_id: Uuid)
        -> Result<Vec<ClientConsent>>;
}

/// Access Token の jti 失効リスト（F5: Token 管理）。
/// JWT は自己完結型のため、jti を本テーブルで管理することで即時失効を実現する。
#[async_trait]
pub trait RevokedAccessTokenRepository: Send + Sync {
    /// jti を失効リストに追加する（冪等）。
    async fn revoke(&self, token: &RevokedAccessToken) -> Result<()>;
    /// 指定 jti が失効リストに存在するか。
    async fn is_revoked(&self, jti: &str) -> Result<bool>;
}

/// ユーザーの TOTP シークレット（MFA 自己登録）。
///
/// `confirmed_at IS NULL` = 仮登録中（QR 確認未完了）。
/// `confirmed_at IS NOT NULL` = 有効化済み（ログイン時に TOTP 検証が必要）。
#[async_trait]
pub trait TotpSecretRepository: Send + Sync {
    /// TOTP シークレットを保存する。既存の場合は上書き（UPSERT）する。
    async fn upsert(&self, secret: &TotpSecret) -> Result<()>;
    /// ユーザーの TOTP シークレットを返す（仮登録中・有効化済みを問わない）。
    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Option<TotpSecret>>;
    /// 確認コードを検証後、`confirmed_at` を設定して有効化する。
    async fn confirm(&self, user_id: Uuid, confirmed_at: DateTime<Utc>) -> Result<()>;
    /// ユーザーの TOTP シークレットを削除する（冪等: 不存在でもエラーにしない）。
    async fn delete(&self, user_id: Uuid) -> Result<()>;
}

/// ユーザーの WebAuthn（FIDO2 Passkey）クレデンシャル。
///
/// 1 ユーザーが複数デバイスを登録できる（ユーザー × デバイスの 1:N 関係）。
/// 認証時は `credential_id` でクレデンシャルを特定し、`passkey_json` を `webauthn-rs` に渡す。
#[async_trait]
pub trait WebAuthnCredentialRepository: Send + Sync {
    /// クレデンシャルを新規登録する。`credential_id` 重複は `Conflict`。
    async fn create(&self, cred: &WebAuthnCredential) -> Result<()>;
    /// 内部 UUID で検索する。
    async fn find_by_id(&self, id: Uuid) -> Result<Option<WebAuthnCredential>>;
    /// WebAuthn credential ID（base64url）で検索する（認証レスポンスからの逆引き用）。
    async fn find_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<WebAuthnCredential>>;
    /// ユーザーの全クレデンシャルを作成日時昇順で返す。
    async fn list_by_user_id(&self, user_id: Uuid) -> Result<Vec<WebAuthnCredential>>;
    /// sign_count と last_used_at を更新し、passkey_json（webauthn-rs による更新後の全体）も保存する。
    async fn update_passkey(
        &self,
        id: Uuid,
        passkey_json: &str,
        last_used_at: DateTime<Utc>,
    ) -> Result<()>;
    /// クレデンシャルを削除する。所有者チェック（`user_id` 照合）も行う。不存在は冪等に無視する。
    async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<()>;
}

/// システム設定（root/idp.system.admin が管理する IdP 全体設定。ADR-0009 §5、MT14）の永続化。
///
/// テナント列を持たず IdP 全体に一律適用する（root のみ管理可能。判定は Presentation の
/// `RequirePerms<IdpSystemAdmin>` が担う）。秘匿値の暗号化・復号は Application 層の責務で、本トレイトは
/// 保存形式（暗号文を含む）の文字列を素通しする。
#[async_trait]
pub trait SystemSettingsRepository: Send + Sync {
    /// 全システム設定を返す（値は保存形式のまま。`is_secret` のものは暗号文）。
    async fn load_all(&self) -> Result<Vec<SystemSetting>>;
    /// 設定を UPSERT する（キー単位。`is_secret` も保存する）。
    async fn upsert(&self, setting: &SystemSetting) -> Result<()>;
}

/// Passkey チャレンジ一時テーブル（WebAuthn の begin → complete 中間状態）。
///
/// `expires_at` を過ぎたレコードはアプリケーション層が削除する。
#[async_trait]
pub trait PasskeyChallengeRepository: Send + Sync {
    /// チャレンジを保存する。
    async fn create(&self, challenge: &PasskeyChallenge) -> Result<()>;
    /// ID でチャレンジを取得する。不存在は `None`。
    async fn find_by_id(&self, id: Uuid) -> Result<Option<PasskeyChallenge>>;
    /// チャレンジを消費（削除）する（complete ステップで使用後に呼ぶ）。
    async fn delete(&self, id: Uuid) -> Result<()>;
    /// 期限切れのチャレンジをまとめて削除する（定期クリーンアップ用）。
    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<()>;
}
