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

use crate::domain::application_log::{
    ApplicationLogEntry, ApplicationLogFilter, ApplicationLogRecord,
};
use crate::domain::audit::{AuditEvent, AuditLogEntry, AuditLogFilter};
use crate::domain::auth_session::AuthSession;
use crate::domain::authentication_policy::{AuthenticationPolicy, LockoutPolicy};
use crate::domain::authorization_code::AuthorizationCode;
use crate::domain::backchannel_logout::BackchannelLogoutDelivery;
use crate::domain::client::Client;
use crate::domain::consent::ClientConsent;
use crate::domain::email_verification::EmailVerificationToken;
use crate::domain::error::Result;
use crate::domain::external_idp::{
    ExternalIdentity, ExternalIdentityProvider, ExternalLoginRequest,
};
use crate::domain::login_identifier::{LoginIdentifierMatch, UserLoginIdentifier};
use crate::domain::paging::{Page, PageRequest};
use crate::domain::passkey_challenge::PasskeyChallenge;
use crate::domain::password_reset::PasswordResetToken;
use crate::domain::refresh_token::RefreshToken;
use crate::domain::revoked_access_token::RevokedAccessToken;
use crate::domain::saml_service_provider::SamlServiceProvider;
use crate::domain::saml_sso_request::SamlSsoRequest;
use crate::domain::signing_key::SigningKey;
use crate::domain::sso_session::SsoSession;
use crate::domain::system_setting::SystemSetting;
use crate::domain::tenant::{Tenant, TenantId};
use crate::domain::tenant_domain::TenantDomain;
use crate::domain::tenant_membership::{TenantMemberFilter, TenantMemberPage, TenantMembership};
use crate::domain::totp_secret::TotpSecret;
use crate::domain::user::{LoginFailureRecord, User};
use crate::domain::user_authenticator::{
    AuthenticatorStatus, AuthenticatorType, UserAuthenticator,
};
use crate::domain::values::{
    AuthenticationMethod, GrantType, MembershipStatus, SigningKeyStatus, UserStatus,
};
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
    /// 指定テナントの直下の子テナントを一覧する（ADR-0009 §6）。件数の上限が無いため、
    /// 画面へ返す経路では [`Self::list_children_page`] を使う（本メソッドは削除可否の判定など
    /// 全件が要る内部用途に限る）。
    async fn list_children(&self, parent_id: TenantId) -> Result<Vec<Tenant>>;
    /// 直下の子テナントを 1 ページ分と総件数で返す（`/{tenant_id}/admin/tenants`。G7）。
    /// 既定実装は全件取得からの切り出しで、DB 側で `LIMIT`/`OFFSET` を書ける sqlx 実装が上書きする。
    async fn list_children_page(
        &self,
        parent_id: TenantId,
        page: PageRequest,
    ) -> Result<Page<Tenant>> {
        Ok(Page::from_all(self.list_children(parent_id).await?, page))
    }
    /// 表示名・状態を更新する（`parent_tenant_id` の付け替えは禁止。呼び出し側が保証する）。
    async fn update(&self, tenant: &Tenant) -> Result<()>;
    /// テナントを削除する。「配下に子テナントが無く、当該テナント自身にユーザー/クライアントが
    /// 存在しない」ことは呼び出し側が事前検証する（DB も `ON DELETE RESTRICT` で保護する）。
    async fn delete(&self, id: TenantId) -> Result<()>;
}

fn unsupported(method: &str) -> crate::domain::error::DomainError {
    crate::domain::error::DomainError::Repository(format!(
        "{method} is not supported by this repository"
    ))
}

/// テナントへ排他的に割り当てたドメイン（ADR-0029）。
///
/// ログイン欄に `local@domain` の形で入力されたとき、ドメインから**所属元テナントを 1 つに決める**
/// ために引く（home realm discovery。`crate::application::login_user_resolution`）。所属元が
/// 決まれば 1 テナントの登録簿だけを引けばよく、参加中のゲストの横断走査を通らずに済む。
#[async_trait]
pub trait TenantDomainRepository: Send + Sync {
    /// ドメインからそれを所有するテナントを引く（**認証のホットパス**）。
    ///
    /// `domain` は正規化済み（[`crate::domain::tenant_domain::normalize_domain`]）で渡す。
    /// 一意キー `tenant_domains_domain_uk` の等値検索 1 本で、結果は高々 1 件である
    /// （2 件当たり得るなら所属元が決まらず、この表を作った意味が無くなる）。
    ///
    /// **テナント解決の TTL キャッシュには載せない。** 割り当ての取り消しが最大 TTL 分効かない
    /// 状態を作らないためで、テナントの `ACTIVE` 判定（ADR-0009 §8）と同じ扱いである。
    ///
    /// 既定実装は `Ok(None)`（ドメインを持たないテスト用フェイクは、従来の解決だけを通る）。
    async fn find_tenant_by_domain(&self, _domain: &str) -> Result<Option<TenantId>> {
        Ok(None)
    }
    /// テナントに割り当てられているドメインを一覧する（管理 API）。
    ///
    /// 以下 3 つの既定実装は**失敗を返す**（`Ok(vec![])` や `Ok(())` にしない）。ログイン経路だけを
    /// 差し替えたいテスト用フェイクが管理操作まで黙って引き受けると、割り当てられていないのに
    /// 成功したように見えてしまう。
    async fn list_for_tenant(&self, _tenant_id: TenantId) -> Result<Vec<TenantDomain>> {
        Err(unsupported("list_for_tenant"))
    }
    /// ドメインを割り当てる。すでに**どこかのテナントが**押さえていれば `Conflict`
    /// （一意キーはテナントを含まない。ADR-0029 §1）。
    async fn create(&self, _domain: &TenantDomain) -> Result<()> {
        Err(unsupported("create"))
    }
    /// 割り当てを解除する。`tenant_id` と一致する行だけを消し、消えたかを返す
    /// （他テナントのドメインを id 指定で消せないようにする）。
    async fn delete(&self, _tenant_id: TenantId, _id: Uuid) -> Result<bool> {
        Err(unsupported("delete"))
    }
}

/// テナント開通（ADR-0009 §5）のトランザクション境界（unit of work）。
///
/// テナント作成は「テナント行・初期管理者ユーザー・HOME メンバーシップ・`idp.tenant.admin` 付与」の
/// 4 行が揃って初めて意味を持つ（どれか欠けると管理者のいないテナント＝孤立テナントが残る）。
/// 本ポートはこの集約を**単一トランザクションで**永続化し、途中失敗時は全体をロールバックする（REF2）。
/// ドメインオブジェクトの構築・検証は Application 層の責務で、実装は永続化のみを担う。
#[async_trait]
pub trait TenantProvisioningRepository: Send + Sync {
    /// テナント・作成者のブートストラップ管理者メンバーシップ・権限付与を原子的に永続化する
    /// （ADR-0009 §4）。作成者ユーザー自体は既存（親テナント所属）のため新規作成しない。
    /// 一意制約違反（root 重複・メンバーシップ重複）は `Conflict`、`admin_permission_code` が
    /// `permissions` マスタに無い場合は `InvalidValue` を返す。
    async fn provision(
        &self,
        tenant: &Tenant,
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
    /// ユーザーが指定テナントで `ACTIVE` なメンバーシップ（HOME または GUEST）を持ち、かつ
    /// **その利用者の所属元テナントが `ACTIVE`** か（OIDC フローのメンバーシップ判定。ADR-0009 §8）。
    ///
    /// **所属元テナントの状態を含める。** 所属元の無効化は「その組織の利用者を止める」操作であり、
    /// 参加先テナント経由の裏口を残す意味ではない。所属元テナントを `DISABLED` にすると、そのテナント
    /// 自身の URL は解決できなくなる（`TenantResolutionService`）が、ゲスト参加先の URL は生きている
    /// ため、ここで見ないと「所属元は止めたのに参加先からは入れる」利用者ができる。
    ///
    /// これは ADR-0009 §1 の「テナントの状態は各テナント独立（親の `DISABLED` は子へ伝播しない）」と
    /// 矛盾しない。§1 は**テナント階層（親→子）**の話で、こちらは**利用者の所属元→その利用者**の話
    /// であり、軸が違う。
    ///
    /// ゲストをログイン欄の入力から引く経路（`UserRepository::find_active_guest_by_login_identifier`）は
    /// 解決クエリの中で同じ条件を課す（メンバーシップの確認と利用者の解決が 1 本のクエリのため）。
    async fn is_active_member(&self, tenant_id: TenantId, user_id: Uuid) -> Result<bool>;
    /// ユーザーが `ACTIVE` なメンバーシップ（HOME / GUEST）を持つ全テナントを返す
    /// （テナント切り替え UI 用。ADR-0009 §3）。`tenant_memberships_user_idx` を用いる。
    /// 既定実装は空（テスト用フェイクは呼ばれない。本番の sqlx 実装のみが上書きする）。
    async fn list_active_for_user(&self, _user_id: Uuid) -> Result<Vec<TenantMembership>> {
        Ok(Vec::new())
    }
    /// 招待トークンのハッシュで `INVITED` 中の行を検索する（承諾エンドポイント用）。
    async fn find_by_invitation_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<TenantMembership>>;
    /// 招待を承諾し、`ACTIVE` へ遷移させる（トークン関連カラムは呼び出し側でクリアする）。
    async fn activate(&self, tenant_id: TenantId, user_id: Uuid) -> Result<()>;
    /// メンバーシップの状態を更新する（`ACTIVE` ⇄ `SUSPENDED` の一時停止・再開。MT24）。
    /// 遷移の可否判定は Application 層（[`crate::domain::tenant_membership::TenantMembership`] の
    /// `can_be_suspended` / `can_be_resumed`）が担い、本メソッドは書き込みのみを行う。
    async fn update_status(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        status: MembershipStatus,
    ) -> Result<()>;
    /// ゲストメンバーシップを解除する（HOME の解除は呼び出し側が禁止する）。
    async fn delete(&self, tenant_id: TenantId, user_id: Uuid) -> Result<()>;
}

/// メンバー一覧（読み取りモデル）の照会（MT22）。書き込み（[`TenantMembershipRepository`]）とは
/// 関心を分ける（`AuditLogSink` と `AuditLogQuery` と同じ分け方）。
///
/// 絞り込みが利用者側の列（メール・氏名）に掛かる一方でページはメンバーシップ単位のため、
/// 実装はメンバーシップと利用者を**結合した 1 クエリ**で解決する（全件を読み込んでから
/// アプリ側で絞る方式は、テナントの規模に比例して破綻するため採らない）。
#[async_trait]
pub trait TenantMemberQuery: Send + Sync {
    /// 条件に一致するメンバーをメールアドレスの昇順（同値は `user_id` 昇順）に 1 ページ分返す。
    /// 並び順は安定でなければならない（ページ間で行が重複・欠落しないため）。
    async fn search(&self, filter: &TenantMemberFilter) -> Result<TenantMemberPage>;
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
    /// 所属元が `tenant_id` のユーザーを email で検索する（一意キーは `(tenant_id, email)`）。
    async fn find_by_email(&self, tenant_id: TenantId, email: &str) -> Result<Option<User>>;
    /// 所属元が `tenant_id` のユーザーを preferred_username で検索する。
    async fn find_by_username(&self, tenant_id: TenantId, username: &str) -> Result<Option<User>>;
    /// **ログイン欄に入力された値**からユーザーを解決する（AP8）。
    ///
    /// 登録簿（`user_login_identifiers`）の有効な行を種別ごとの正規化キーで引き、無ければ
    /// `users.preferred_username` へ落とす。ログイン識別子の複数化は「入力の読み方が増える」
    /// 変更であって「ユーザーの引き方が増える」変更ではないため、ログイン各経路には**この 1 本**
    /// だけを見せ、どこを引いたかは実装に閉じる。
    ///
    /// 既定実装は `find_by_username` に委譲する（登録簿を持たないテスト用フェイクは、
    /// 従来どおり `preferred_username` だけで解決される）。
    async fn find_by_login_identifier(
        &self,
        tenant_id: TenantId,
        input: &str,
    ) -> Result<LoginIdentifierMatch> {
        Ok(self.find_by_username(tenant_id, input.trim()).await?.into())
    }
    /// **参加先テナントのログイン画面**に入力された値から、そのテナントの ACTIVE な GUEST を
    /// 解決する（ADR-0009 §8）。
    ///
    /// ゲストの識別子は所属元テナントの登録簿にあるため、要求テナントで登録簿を引く
    /// [`Self::find_by_login_identifier`] には掛からない。こちらは「`tenant_id` に ACTIVE な GUEST
    /// メンバーシップを持つ利用者の、**所属元テナントの**有効な識別子」を引く。
    ///
    /// 呼ぶのはログイン経路だけで、しかも**所属元での解決が空振りしたときに限る**
    /// （[`crate::application::login_user_resolution::resolve_login_user`]）。所属元を先に決めるのは、
    /// 同じ値の識別子を持つゲストが参加してきただけで、そのテナントの HOME 利用者が「曖昧」に
    /// なって締め出されるのを防ぐため。
    ///
    /// 既定実装は `NotFound`（メンバーシップを持たないテスト用フェイクは、従来どおり所属元だけで
    /// 解決される）。
    async fn find_active_guest_by_login_identifier(
        &self,
        _tenant_id: TenantId,
        _input: &str,
    ) -> Result<LoginIdentifierMatch> {
        Ok(LoginIdentifierMatch::not_found())
    }
    /// **参加先テナントのパスワード再設定**（`/{tenant_id}/forgot-password`）から、そのテナントの
    /// ACTIVE な GUEST を `users.email` で引く（MT26）。
    ///
    /// 再設定はログインと違い**登録簿（`user_login_identifiers`）ではなく `users.email` で引く**。
    /// メールの届け先そのものだからで、メールでのログインを有効にしていないテナントでも成り立つ
    /// 必要がある（ADR-0025 §5）。そのため
    /// [`Self::find_active_guest_by_login_identifier`] は使えず、この引き方が別に要る。
    ///
    /// 条件はゲスト解決と同じ「要求テナントの ACTIVE な GUEST × 所属元テナントが ACTIVE」。
    /// **複数人に当たったら誰も返さない** —— `users.email` の一意性はテナント内でしか無く、所属元の
    /// 違うゲストが同じアドレスを持ち得る。どちらへ送るか決められない以上、送らない
    /// （応答は常に `Accepted` なので、利用者から見た振る舞いは「メールが来ない」で変わらない）。
    ///
    /// 既定実装は `Ok(None)`（メンバーシップを持たないテスト用フェイクは所属元だけで解決する）。
    async fn find_active_guest_by_email(
        &self,
        _tenant_id: TenantId,
        _email: &str,
    ) -> Result<Option<User>> {
        Ok(None)
    }
    /// **所属元テナントが分かっているとき**に、そのテナントの登録簿だけを引く（ADR-0029）。
    ///
    /// 呼ぶのはログイン経路で、入力が `local@domain` の形をしていてそのドメインが
    /// [`TenantDomainRepository::find_tenant_by_domain`] で 1 つのテナントに解決できたときに限る
    /// （home realm discovery）。`home_tenant_id` はそうして決まった所属元テナントである。
    ///
    /// 解決の条件は [`Self::find_active_guest_by_login_identifier`] と同じ「要求テナントで ACTIVE な
    /// メンバー ×  所属元テナントが ACTIVE」だが、**メンバーシップ種別で絞らない**（所属元が
    /// 決まっている以上、HOME でも GUEST でも同じ扱いでよい）。要求テナント自身がドメインを持つ
    /// 場合もこの経路を通り、その利用者は HOME メンバーとして解決される。
    ///
    /// **この経路では曖昧さが原理的に起きない。** 引くのは 1 テナントの登録簿だけで、その中では
    /// 1 正規化値が 1 人のものだからである（migration 0041）。ゲストの横断走査
    /// （[`Self::find_active_guest_by_login_identifier`]）が「同名のゲストが 2 人参加すると双方が
    /// 締め出される」原因なので、そこを通らずに済むこと自体が本メソッドの目的である。
    ///
    /// 既定実装は `NotFound`（ドメインを持たないテスト用フェイクは、従来の解決だけを通る）。
    async fn find_member_by_login_identifier(
        &self,
        _tenant_id: TenantId,
        _home_tenant_id: TenantId,
        _input: &str,
    ) -> Result<LoginIdentifierMatch> {
        Ok(LoginIdentifierMatch::not_found())
    }
    /// ログイン失敗回数・ロック期限を更新する（ロックポリシー、設計仕様 §4.3）。
    ///
    /// **失敗の記録には使わない**（[`Self::record_login_failure`] を使う）。読んだ値を +1 して
    /// 書き戻すと並行試行で取りこぼす。こちらは「成功時のリセット」「管理者による解除」のように
    /// 絶対値を書く用途に限る。
    async fn update_login_state(
        &self,
        id: Uuid,
        failed_login_count: i32,
        locked_until: Option<DateTime<Utc>>,
    ) -> Result<()>;
    /// ログイン失敗を 1 件記録し、記録後の状態を返す（SEC13）。
    ///
    /// 加算とロック判定を**1 文**で行う。「読む → +1 して書き戻す」だと、並行して届いた N 件の
    /// 試行が同じ値を読み、N 回失敗しても失敗回数が 1 しか進まずロック閾値に届かないことがある。
    /// ロックは多層防御の一枚（IP 単位のレート制限とは別の層）なので、取りこぼさない。
    ///
    /// ロック判定を呼び出し側に残さないのは、閾値の比較対象になる失敗回数が
    /// **この UPDATE の中でしか正しく分からない**ためである。
    async fn record_login_failure(
        &self,
        id: Uuid,
        lockout: LockoutPolicy,
        now: DateTime<Utc>,
    ) -> Result<LoginFailureRecord>;
    /// パスワードハッシュを更新し、`must_change_password` を解除する（パスワード変更、ADR-0009 §5）。
    ///
    /// **現行ハッシュが `expected_current_hash` のままである場合にだけ**書き換え、書き換えたら
    /// `true` を返す。`false` は「読んでから書くまでの間に別の要求がパスワードを変えた」を意味する。
    ///
    /// 条件付きにするのは、履歴（AP7）が**実際に置き換えた**ハッシュでなければ意味を持たないため。
    /// 無条件の UPDATE だと、同時に届いた 2 つの変更要求が同じ現行ハッシュを読み、後勝ちで
    /// 上書きしたうえで**両方が同じ古いハッシュを履歴へ積む** —— 先に書かれたパスワードは現行にも
    /// 履歴にも残らず、直後に再利用できてしまう。
    async fn update_password(
        &self,
        id: Uuid,
        expected_current_hash: &str,
        password_hash: &str,
    ) -> Result<bool>;
    /// パスワードハッシュを更新し、`must_change_password` を**設定**する（管理者による再発行。
    /// 次回ログインで本人に変更させる。ADR-0009 §5）。条件と戻り値は
    /// [`Self::update_password`] と同じ。
    async fn reset_password_forced(
        &self,
        id: Uuid,
        expected_current_hash: &str,
        password_hash: &str,
    ) -> Result<bool>;
    /// 利用者の状態（ACTIVE / DISABLED / LOCKED）を更新する（管理者による有効化・無効化）。
    async fn update_status(&self, id: Uuid, status: UserStatus) -> Result<()>;
    /// 利用者を削除する（管理者による削除。関連行は DB の FK CASCADE / SET NULL で後始末される）。
    async fn delete(&self, id: Uuid) -> Result<()>;
    /// メール検証済みフラグを立てる（自己登録アカウントの確認リンク消費時。SEC6b）。
    async fn mark_email_verified(&self, id: Uuid) -> Result<()>;
    /// 表示言語設定を更新する（MT20。`None` で設定解除）。
    async fn update_language(&self, id: Uuid, language: Option<&str>) -> Result<()>;
    /// 配色設定を更新する（`light` / `dark` / `system`。`None` で設定解除）。
    /// 既定実装は未対応エラー（本番の sqlx 実装のみが上書きする。テスト用フェイクは呼ばれない）。
    async fn update_theme(&self, _id: Uuid, _theme: Option<&str>) -> Result<()> {
        Err(crate::domain::error::DomainError::Repository(
            "update_theme is not supported by this repository".to_string(),
        ))
    }
    /// 表示名（`users.name`）を更新する（セルフサービス。`None` で表示名を解除＝`NULL`）。
    /// 既定実装は未対応エラー（本番の sqlx 実装のみが上書きする。テスト用フェイクは呼ばれない）。
    async fn update_name(&self, _id: Uuid, _name: Option<&str>) -> Result<()> {
        Err(crate::domain::error::DomainError::Repository(
            "update_name is not supported by this repository".to_string(),
        ))
    }
    /// プロフィール（メール・ログイン識別子・表示名）をまとめて更新する（管理者による編集。MT25）。
    /// `preferred_username` / `name` の `None` は「解除（`NULL`）」を意味する。テナント内の
    /// `(tenant_id, email)` / `(tenant_id, preferred_username)` 一意制約違反は `Conflict` を返す。
    /// 既定実装は未対応エラー（`update_name` と同じ方針。本番の sqlx 実装のみが上書きする）。
    async fn update_profile(
        &self,
        _id: Uuid,
        _email: &str,
        _preferred_username: Option<&str>,
        _name: Option<&str>,
    ) -> Result<()> {
        Err(crate::domain::error::DomainError::Repository(
            "update_profile is not supported by this repository".to_string(),
        ))
    }
}

/// ログイン識別子の登録簿（AP8。`user_login_identifiers`）の永続化。
///
/// 解決（ログイン時の引き当て）は [`UserRepository::find_by_login_identifier`] にあり、ここには
/// **管理操作**（一覧・追加・有効/無効・削除・プロフィール同期）だけを置く。読みのホットパスと
/// 管理の書き込みで関心が違うためで、`AuditLogSink` と `AuditLogQuery` と同じ分け方をしている。
///
/// 既定実装は「登録簿が空」として振る舞う（登録簿を持たないテスト用フェイクのため。AP9 の
/// [`UserAuthenticatorRepository`] と同じ方針）。
#[async_trait]
pub trait UserLoginIdentifierRepository: Send + Sync {
    /// 識別子を登録する。テナント内で `normalized_value` が重複したら `Conflict`
    /// （**種別に依存しない**。1 正規化値は 1 人のもの。migration 0041）。
    async fn create(&self, _identifier: &UserLoginIdentifier) -> Result<()> {
        Err(crate::domain::error::DomainError::Repository(
            "create is not supported by this repository".to_string(),
        ))
    }
    /// 利用者の識別子を種別・登録順に一覧する（無効な行も含む。管理画面用）。
    async fn list_for_user(&self, _user_id: Uuid) -> Result<Vec<UserLoginIdentifier>> {
        Ok(Vec::new())
    }
    /// 内部 ID で引く（テナント境界の確認は呼び出し側が行う）。
    async fn find_by_id(&self, _id: Uuid) -> Result<Option<UserLoginIdentifier>> {
        Ok(None)
    }
    /// 有効/無効を切り替える。対象（`(id, user_id)`）が無ければ `false`。
    async fn set_active(&self, _id: Uuid, _user_id: Uuid, _is_active: bool) -> Result<bool> {
        Ok(false)
    }
    /// 識別子を削除する。対象（`(id, user_id)`）が無ければ `false`。
    async fn delete(&self, _id: Uuid, _user_id: Uuid) -> Result<bool> {
        Ok(false)
    }
}

/// 検証を通った client assertion の `jti` を記録し、有効期間内の再利用を拒む（ADR-0030 決定 5）。
///
/// 期限切れ行の掃除は本トレイトではなく共通の GC（`ExpiringRecordStore`）が行う。
///
/// `jti` の一意性はクライアントの中でしか要求できない（RFC 7519 §4.1.7 も発行者ごとの一意性しか
/// 定めない）ため、鍵は `(tenant_id, client_id, jti)` の 3 つ組になる。
#[async_trait]
pub trait ClientAssertionReplayRepository: Send + Sync {
    /// `jti` が未使用なら記録して `true`、既に記録済みなら `false`（＝再生）を返す。
    ///
    /// 「確認してから書く」の 2 段階にすると、同じ assertion の同時到着が両方とも未使用と判定
    /// され得る。実装は一意制約への挿入 1 回で判定すること。
    ///
    /// `retain_until` は記録を残す時刻。assertion の `exp` そのものではなく、**受理が止まる時刻**
    /// （`exp` ＋ 時計ずれの許容幅）を渡す。`exp` までしか残さないと、掃除で行が消えた後も受理は
    /// 続く隙間ができ、そこで同じ assertion を再利用できてしまう。
    async fn record_if_unused(
        &self,
        tenant_id: TenantId,
        client_id: &str,
        jti: &str,
        retain_until: DateTime<Utc>,
    ) -> Result<bool>;
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
    /// 指定テナントの登録済みクライアントを新しい順に**全件**一覧する。
    /// CORS 許可オリジンの収集・バックチャネルログアウトの配信先解決など、
    /// 全件が要る内部用途のためのメソッド。画面へ返す経路では [`Self::list_page`] を使う。
    async fn list(&self, tenant_id: TenantId) -> Result<Vec<Client>>;
    /// 登録済みクライアントを 1 ページ分と総件数で返す（`/{tenant_id}/admin/clients`。G7）。
    /// 既定実装は全件取得からの切り出しで、DB 側で `LIMIT`/`OFFSET` を書ける sqlx 実装が上書きする。
    /// 1 ページ分と総件数を返す。`grant_type` を渡すと、その grant を登録済みのクライアントだけに
    /// 絞る（ADR-0038。管理コンソールの「連携先」と「サービスアカウント」の一覧がこれで分かれる）。
    ///
    /// **絞り込みはページングと同じ層で行う必要がある。** 呼び出し側が 1 ページを受け取ってから
    /// 間引くと、`total` もページャも実際の件数と合わなくなる。
    async fn list_page(
        &self,
        tenant_id: TenantId,
        grant_type: Option<GrantType>,
        page: PageRequest,
    ) -> Result<Page<Client>> {
        let all = self.list(tenant_id).await?;
        let filtered = match grant_type {
            Some(grant) => all
                .into_iter()
                .filter(|c| c.allows_grant_type(grant))
                .collect(),
            None => all,
        };
        Ok(Page::from_all(filtered, page))
    }
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
    /// テナント境界内で entity_id 解決する（SSO エンドポイントの AuthnRequest `Issuer` 照合。
    /// `(tenant_id, entity_id)` は一意）。
    async fn find_by_entity_id(
        &self,
        tenant_id: TenantId,
        entity_id: &str,
    ) -> Result<Option<SamlServiceProvider>>;
    /// 既存 SP を更新する（同一テナント・id のレコードのみ。entity_id 重複は `Conflict`）。
    /// 更新できた場合 `true`、対象が無ければ（find 後に別管理者が削除した競合等）`false`。
    async fn update(&self, provider: &SamlServiceProvider) -> Result<bool>;
    /// テナント境界内で SP を削除する。削除できた場合 `true`、対象が無ければ `false`。
    async fn delete(&self, tenant_id: TenantId, id: Uuid) -> Result<bool>;
}

/// SAML SP-initiated SSO の進行状態（`saml_sso_requests`）の永続化。
/// ハンドルの単回消費は [`AuthSessionRepository`] と同じ原子的 UPDATE 方式で強制する。
/// SAML SP-initiated SSO の進行状態の永続化。
///
/// [`AuthSessionRepository`] と同じく **`saml_request_id` の平文を受け取らない**。引数の
/// `id_hash` は [`crate::domain::saml_sso_request::id_hash`] で導出した SHA-256 である（SEC6）。
#[async_trait]
pub trait SamlSsoRequestRepository: Send + Sync {
    async fn create(&self, request: &SamlSsoRequest) -> Result<()>;
    /// フローを開始したテナントの行のみ返す（他テナントの id を持ち込んでも解決させない）。
    async fn find_by_id_hash(
        &self,
        tenant_id: TenantId,
        id_hash: &str,
    ) -> Result<Option<SamlSsoRequest>>;
    /// web ハンドオフ用ハンドル（SHA-256）で行を引く。テナント限定は `find_by_id_hash` と同じ。
    async fn find_by_handle(
        &self,
        tenant_id: TenantId,
        handle_hash: &str,
    ) -> Result<Option<SamlSsoRequest>>;
    /// ハンドルを単回使用として消費し（`handle_hash` を NULL 化）、**同時に id を `new_id_hash`
    /// へ再生成する**。すでに消費済み（並行交換に負けた・再利用）なら `false` を返す。
    /// 再生成が要る理由は [`AuthSessionRepository::consume_handle`] と同じ。
    async fn consume_handle(
        &self,
        id_hash: &str,
        handle_hash: &str,
        new_id_hash: &str,
    ) -> Result<bool>;
    /// 進行状態を削除する。応答発行前の**原子的なクレーム**を兼ねるため、削除できた場合のみ
    /// `true` を返す（並行 resume に負けた・消費済みなら `false` = 発行不可）。
    async fn delete(&self, id_hash: &str) -> Result<bool>;
    /// 期限切れの行を削除し、削除件数を返す（G2 の一括 GC から呼ぶ）。
    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<u64>;
}

/// 認可フローの一時状態（`/authorize` 〜 `/login` 完了）の永続化。
///
/// **本トレイトは `auth_session_id` の平文を一切受け取らない。** 引数の `id_hash` は
/// [`crate::domain::auth_session::id_hash`] で導出した SHA-256 で、平文は Application 層より
/// 上（web の Cookie・ハンドオフ）にしか存在しない（SEC6）。平文を渡す口を作らないことで、
/// 「うっかり生値を保存する」経路を型の上で塞いでいる。
#[async_trait]
pub trait AuthSessionRepository: Send + Sync {
    async fn create(&self, session: &AuthSession) -> Result<()>;
    /// フローを開始したテナントの auth session のみ返す（他テナントの session id を
    /// 持ち込んでも解決させない）。
    async fn find_by_id_hash(
        &self,
        tenant_id: TenantId,
        id_hash: &str,
    ) -> Result<Option<AuthSession>>;
    /// web ハンドオフ用ハンドル（SHA-256）で auth session を引く（ADR-0018 決定 2）。
    /// `find_by_id_hash` と同じくフローのテナントに限定する。期限・消費済み判定は Application 層が行う。
    async fn find_by_handle(
        &self,
        tenant_id: TenantId,
        handle_hash: &str,
    ) -> Result<Option<AuthSession>>;
    /// ハンドルを単回使用として消費し（`handle_hash` を NULL 化）、**同時に id を
    /// `new_id_hash` へ再生成する**。すでに消費済み（並行交換に負けた・再利用）なら `false` を返す。
    ///
    /// 交換と再生成を 1 文にまとめてあるのは、ハンドル経路では平文 id が手元に無いためである。
    /// DB にはハッシュしか無く（SEC6）平文へ戻せないので、ハンドルを渡した web へ返す
    /// `auth_session_id` は交換の時点で新しく作るしかない。ハンドル自体が単回使用なので、
    /// この再生成はフロー 1 本につき 1 回だけ起きる。
    async fn consume_handle(
        &self,
        id_hash: &str,
        handle_hash: &str,
        new_id_hash: &str,
    ) -> Result<bool>;
    /// 認証済みユーザーと `auth_time`、確立した SSO セッションの `sid` を設定し、**同時に id を
    /// `new_id_hash` へ再生成する**（`/login` 成功時。SEC7）。
    ///
    /// `sso_sid` は同意画面を挟む経路（`ConsentService::approve`）が code 発行時に読む（G5）。
    /// 認証と code 発行が別リクエストに分かれ、その時点では SSO Cookie が手元に無いため、
    /// ここで auth_session へ預ける。
    ///
    /// id の再生成（セッション固定攻撃対策）を独立したメソッドにせず記録と 1 文にまとめてあるのは、
    /// 「認証前に発行した Cookie 値が認証後も通る瞬間」を作らないためである。`sso_session_id` は
    /// ログインのたびに再生成しており（`SsoSession::establish`）、それと非対称にしない。
    async fn set_authenticated_user(
        &self,
        id_hash: &str,
        new_id_hash: &str,
        user_id: Uuid,
        auth_time: DateTime<Utc>,
        sso_sid: Option<&str>,
    ) -> Result<()>;
    /// パスワード検証成功後に MFA pending 状態を記録し（`password_verified_at` を設定）、
    /// **同時に id を `new_id_hash` へ再生成する**（SEC7。理由は
    /// [`set_authenticated_user`](Self::set_authenticated_user) 参照）。
    async fn set_password_verified(
        &self,
        id_hash: &str,
        new_id_hash: &str,
        user_id: Uuid,
        verified_at: DateTime<Utc>,
    ) -> Result<()>;
    async fn delete(&self, id_hash: &str) -> Result<()>;
    /// 期限切れの行を削除し、削除件数を返す（G2 の一括 GC から呼ぶ）。
    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<u64>;
}

/// 認証ポリシー（ユーザー認証・認証ポリシー仕様書 §7）の永続化。テナント境界は `tenant_id` で強制する。
///
/// 評価（[`crate::domain::authentication_policy::evaluate_policies`]）はドメインの純粋関数が担い、
/// 本トレイトは行の読み書きのみを担う。ログインのホットパスは `list_enabled_for_tenant` を使う。
#[async_trait]
pub trait AuthenticationPolicyRepository: Send + Sync {
    /// ポリシーを作成する。`(tenant_id, policy_code)` 重複は `Conflict`。
    async fn create(&self, policy: &AuthenticationPolicy) -> Result<()>;
    /// テナントの全ポリシー（無効を含む）を priority 昇順（同値は policy_code 昇順）で返す（管理画面用）。
    async fn list_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<AuthenticationPolicy>>;
    /// テナントの**有効な**ポリシーのみを priority 昇順で返す（ログイン時の評価用）。
    async fn list_enabled_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<AuthenticationPolicy>>;
    /// テナント境界内で id 解決する（他テナントの id を持ち込んでも解決させない）。
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> Result<Option<AuthenticationPolicy>>;
    /// 既存ポリシーを更新する（同一テナント・id の行のみ。policy_code 重複は `Conflict`）。
    /// 更新できた場合 `true`、対象が無ければ `false`。
    async fn update(&self, policy: &AuthenticationPolicy) -> Result<bool>;
    /// テナント境界内でポリシーを削除する。削除できた場合 `true`、対象が無ければ `false`。
    async fn delete(&self, tenant_id: TenantId, id: Uuid) -> Result<bool>;
}

#[async_trait]
pub trait SsoSessionRepository: Send + Sync {
    async fn create(&self, session: &SsoSession) -> Result<()>;
    async fn find_by_hash(&self, session_hash: &str) -> Result<Option<SsoSession>>;
    /// 指定ユーザーの全 SSO セッションを新しい順に返す（セルフサービスのセッション一覧。G10）。
    /// 期限切れ行の除外は呼び出し側（Application 層）が `is_valid_at` で行う。
    /// 既定実装は空（テスト用フェイクは呼ばれない。本番の sqlx 実装のみが上書きする）。
    async fn list_for_user(&self, _user_id: Uuid) -> Result<Vec<SsoSession>> {
        Ok(Vec::new())
    }
    /// SSO 復元時に idle 期限を延長する（absolute は変更しない、設計仕様 §3.4）。
    async fn extend_idle(&self, session_hash: &str, idle_expires_at: DateTime<Utc>) -> Result<()>;
    /// 第二要素の検証完了を記録する（AP4・AP5。Step-up 認証で既存セッションを昇格させる経路）。
    /// `methods` は昇格後の全認証方式で、強度は実装が [`AuthenticationStrength::from_methods`]
    /// で導出する（導出規則の単一の出所をドメインに置くため、呼び出し側は強度を渡さない）。
    /// 既定実装は未対応エラー（本番の sqlx 実装のみが上書きする）。
    async fn record_second_factor(
        &self,
        _session_hash: &str,
        _methods: &[AuthenticationMethod],
        _completed_at: DateTime<Utc>,
    ) -> Result<()> {
        Err(crate::domain::error::DomainError::Repository(
            "record_second_factor is not supported by this repository".to_string(),
        ))
    }
    /// Step-up 認証（AP5）の完了を記録する。`methods` はこの step-up で検証した方式で、
    /// 第二要素を含む場合のみ `mfa_completed_at` と強度も更新する（単一要素の再確認で多要素
    /// セッションを格下げしない・MFA の鮮度を回復させない、が実装の責務）。
    /// 既定実装は未対応エラー（本番の sqlx 実装のみが上書きする）。
    async fn record_step_up(
        &self,
        _session_hash: &str,
        _methods: &[AuthenticationMethod],
        _verified_at: DateTime<Utc>,
    ) -> Result<()> {
        Err(crate::domain::error::DomainError::Repository(
            "record_step_up is not supported by this repository".to_string(),
        ))
    }
    async fn delete(&self, session_hash: &str) -> Result<()>;
    /// 指定ユーザーの全 SSO セッションを削除する（ユーザー単位の全セッション無効化、F5）。
    async fn delete_all_for_user(&self, user_id: Uuid) -> Result<()>;
    /// 期限切れ（idle または absolute 超過）のセッションをまとめて削除し、削除件数を返す（GC）。
    /// 既定実装は何もしない（テスト用フェイクは呼ばれない）。
    async fn delete_expired(&self, _now: DateTime<Utc>) -> Result<u64> {
        Ok(0)
    }
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
    /// **すでに消費済み**の code を hash で引く（SEC8）。`consume` が `None` を返したときに
    /// 「本当の再利用」と「不存在・期限切れ」を切り分けるために使う。未消費・不存在・期限切れで
    /// 削除済み・他テナント発行はいずれも `None`。
    async fn find_used(
        &self,
        tenant_id: TenantId,
        code_hash: &str,
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

/// 退役したパスワードハッシュの履歴（AP7 の再利用禁止）。
///
/// 現行パスワードは `users.password_hash` にあるため、ここには**置き換えられたハッシュ**だけを
/// 積む（写しを持つと更新漏れで履歴と現行がずれる）。ユーザー単位のセキュリティ操作のため
/// tenant_id は取らない（テナント境界はユースケース側が `users.tenant_id` 照合で強制する）。
#[async_trait]
pub trait PasswordHistoryRepository: Send + Sync {
    /// 退役したハッシュを 1 件積み、`retain` 件だけを残して古い行を削除する。
    ///
    /// 積むことと剪定することを分けないのは、片方だけが実行されると履歴が単調増加するか、
    /// 逆に判定に要る件数を割るためである（呼び出し側に順序を守らせない）。
    async fn push(
        &self,
        user_id: Uuid,
        password_hash: &str,
        retired_at: DateTime<Utc>,
        retain: u32,
    ) -> Result<()>;
    /// 新しい順に最大 `limit` 件の退役ハッシュを返す。
    async fn recent(&self, user_id: Uuid, limit: u32) -> Result<Vec<String>>;
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
    /// **いま署名できる鍵が 1 本も無い場合に限り** `key` を挿入する（ブートストラップ専用の
    /// 排他挿入）。判定条件は `find_active` と同じ（ACTIVE かつ有効期間内）—— 公開しただけの
    /// 後継鍵や期限切れのまま ACTIVE で残った鍵は「鍵がある」とは数えない。
    /// 挿入したら `true`、既に署名できる鍵が存在して何もしなかったら `false` を返す。
    /// 「存在確認 → 挿入」を排他区間で行い、複数インスタンスの同時起動でも鍵が
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

    /// 保持期間を過ぎた監査イベントを削除し、削除件数を返す（G8）。削除は書き込み側の関心のため
    /// 読み取り（[`AuditLogQuery`]）ではなく本トレイトに置く。
    ///
    /// 既定実装は何もしない（テスト用フェイクは保持期間を持たない）。本番の sqlx 実装が上書きする。
    async fn purge_older_than(&self, _older_than: DateTime<Utc>) -> Result<u64> {
        Ok(0)
    }
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

/// アプリケーションログ（`log`）の書き込み（CLAUDE.md「ログ」）。`tracing` の WARN / ERROR を
/// 非同期にまとめて永続化する。**ここでの失敗はログに出さない**（書き込み失敗のログがまた書き込みを
/// 誘発する無限ループを避けるため。実装側で握り潰す）。
#[async_trait]
pub trait ApplicationLogSink: Send + Sync {
    /// 複数件をまとめて記録する。空スライスは何もしない。
    async fn record_batch(&self, records: &[ApplicationLogRecord]) -> Result<()>;

    /// `older_than` より古い行を削除し、削除件数を返す（保持期間の適用）。
    async fn purge_older_than(&self, older_than: DateTime<Utc>) -> Result<u64>;
}

/// `log` の読み取り（管理コンソールのエラー・警告ログ画面）。書き込みとは関心を分ける。
#[async_trait]
pub trait ApplicationLogQuery: Send + Sync {
    /// 条件に一致するログを新しい順（`occurred_at` 降順、同時刻は `id` 降順）に返す。
    async fn search(&self, filter: &ApplicationLogFilter) -> Result<Vec<ApplicationLogEntry>>;
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

/// クライアント（システム用クライアント）が保有する権限の永続化（ADR-0037）。
///
/// scope 引数を取らないのは、`clients.id` が既に所属テナントを決めているためである
/// （`clients.tenant_id`）。「クライアントの所属テナント」と「権限の scope」が食い違う状態を
/// そもそも表現できないようにしてある（`client_permissions` に scope 列は無い）。
#[async_trait]
pub trait ClientPermissionRepository: Send + Sync {
    /// 当該クライアントが保有する権限コード一覧を返す（順序は不定。不保有なら空）。
    async fn list_codes_for_client(&self, client_row_id: Uuid) -> Result<Vec<String>>;
    /// 権限を付与する（冪等: 既存付与は `granted_at` を保持する）。
    /// `code` は `permissions` マスタに存在し、かつクライアントへ付与可能であること
    /// （`domain::permission::is_grantable_to_client`。DB 側の CHECK 制約と二重に効く）。
    async fn grant(&self, client_row_id: Uuid, code: &str, granted_at: DateTime<Utc>)
        -> Result<()>;
    /// 権限を剥奪する（不存在でもエラーにしない）。
    async fn revoke(&self, client_row_id: Uuid, code: &str) -> Result<()>;
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
    /// 指定 hash のトークンを失効させる（`revoked_at` を設定）。失効させた行数を返す。
    /// 不存在・既失効でもエラーにしない（冪等。その場合は `0`）。
    ///
    /// 行数を返すのは `/revoke` が「refresh_token として失効させられたか」を判断するため
    /// （RFC 7009 §2.1。失効できなかったなら access_token として試し直す必要がある）。
    async fn revoke(&self, token_hash: &str, revoked_at: DateTime<Utc>) -> Result<u64>;
    /// `parent_hash` でチェーンを検索し、存在する（未失効・失効問わず）場合は `true`。
    /// reuse detection で同一 parent から二重発行が起きていないかを確認するために使う。
    async fn exists_by_parent_hash(&self, parent_hash: &str) -> Result<bool>;
    /// 同一の認可グラントから発行されたトークンファミリを一括失効させる（SEC8）。
    /// `family_hash` は [`RefreshToken::family_hash`](crate::domain::refresh_token::RefreshToken::family_hash)
    /// の値、または authorization code の SHA-256。失効させた行数を返す（監査に載せる）。
    ///
    /// 再利用を検知したときに提示されたトークンだけを失効させると、そこから rotation 済みの
    /// **子孫が有効なまま残る**（攻撃者が先に交換していれば攻撃者側が生き残る）。RFC 6819 §5.2.2.3 /
    /// OAuth 2.1 は同一グラント由来のトークンをまとめて失効させることを求めている。
    async fn revoke_family(
        &self,
        tenant_id: TenantId,
        family_hash: &str,
        revoked_at: DateTime<Utc>,
    ) -> Result<u64>;
    /// 指定ユーザーの全 Refresh Token を失効させる（ユーザー単位の全セッション無効化、F5）。
    async fn revoke_all_for_user(&self, user_id: Uuid, revoked_at: DateTime<Utc>) -> Result<()>;
    /// 指定テナントで発行済みの refresh token をまとめて失効させる（ゲストの一時停止。MT24）。
    ///
    /// ユーザー単位の全失効（[`revoke_all_for_user`](Self::revoke_all_for_user)）と違い、**他テナントでの
    /// 利用は妨げない**。ゲストの停止は 1 つのテナントに対する措置であり、その利用者が所属元テナントで
    /// 使っているトークンまで巻き込んではいけない。
    async fn revoke_all_for_user_in_tenant(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<()>;

    /// 指定テナントの**1 クライアント**へ発行済みの refresh token を失効させる（連携解除。G10）。
    ///
    /// 利用者が 1 つのアプリの連携を解除したときに、同じテナントの他のアプリまで巻き込まないための
    /// 単位。テナント単位の全失効（[`revoke_all_for_user_in_tenant`](Self::revoke_all_for_user_in_tenant)）
    /// は管理者によるゲスト停止のための措置で、目的が違う。
    async fn revoke_all_for_user_and_client(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        client_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> Result<()>;
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

/// Back-channel logout 送信要求の永続キュー（G5）。
///
/// ログアウト処理（同期）は [`enqueue`](Self::enqueue) で要求を積むだけにし、送信はワーカーが
/// [`claim_due`](Self::claim_due) で取り出して行う。「HTTP 送信の成否がログアウト応答を遅らせない」
/// ことと「プロセスが落ちても未送信が消えない」ことを同時に満たすための分離。
#[async_trait]
pub trait BackchannelLogoutDeliveryRepository: Send + Sync {
    /// 送信要求をまとめて積む（空スライスは何もしない）。
    async fn enqueue(&self, deliveries: &[BackchannelLogoutDelivery]) -> Result<()>;

    /// 送信すべき要求を取り出して**試行回数を進め、次回時刻を押し出す**（原子的なクレーム）。
    ///
    /// 対象は「未送信」「`next_attempt_at <= now`」「`attempts < max_attempts`」の行。取り出しと
    /// 更新を分けると、同じ行を二重に送ってしまう（RP から見て重複配送になる）ため実装は原子的に行う。
    /// 返す行は更新後の状態（`attempts` は加算済み）。
    async fn claim_due(
        &self,
        now: DateTime<Utc>,
        max_attempts: i32,
        limit: u32,
    ) -> Result<Vec<BackchannelLogoutDelivery>>;

    /// 送信成功を記録する（`delivered_at` を設定）。
    async fn mark_delivered(&self, id: Uuid, delivered_at: DateTime<Utc>) -> Result<()>;

    /// 送信失敗を記録する（次回試行時刻と直近の失敗理由）。試行回数は
    /// [`claim_due`](Self::claim_due) で加算済みのため、ここでは進めない。
    async fn mark_failed(
        &self,
        id: Uuid,
        next_attempt_at: DateTime<Utc>,
        error: &str,
    ) -> Result<()>;

    /// 決着済み（送信成功、または試行上限に達した）の古い行を削除し、削除件数を返す。
    async fn purge_settled(&self, older_than: DateTime<Utc>, max_attempts: i32) -> Result<u64>;
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

/// 外部 IdP 設定（AP10。仕様 §13）の永続化。テナント境界は `tenant_id` で強制する。
#[async_trait]
pub trait ExternalIdentityProviderRepository: Send + Sync {
    async fn create(&self, provider: &ExternalIdentityProvider) -> Result<()>;
    /// テナントの全プロバイダを `provider_code` 昇順で返す（管理画面用）。
    async fn list_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<ExternalIdentityProvider>>;
    /// テナントの**有効な**プロバイダのみ返す（ログイン画面のボタン用）。
    async fn list_enabled_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<ExternalIdentityProvider>>;
    /// テナント境界内で `provider_code` 解決する（他テナントのコードを持ち込んでも解決させない）。
    async fn find_by_code(
        &self,
        tenant_id: TenantId,
        provider_code: &str,
    ) -> Result<Option<ExternalIdentityProvider>>;
    /// テナント境界内で id 解決する。
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> Result<Option<ExternalIdentityProvider>>;
    /// 既存プロバイダを更新する。更新できた場合 `true`、対象が無ければ `false`。
    async fn update(&self, provider: &ExternalIdentityProvider) -> Result<bool>;
    /// テナント境界内で削除する。削除できた場合 `true`。
    async fn delete(&self, tenant_id: TenantId, id: Uuid) -> Result<bool>;
}

/// 外部 IdP 上の同一性と本 IdP 利用者の対応（AP10。仕様 §13.2）の永続化。
///
/// 検索キーは `(provider_id, external_subject)` で、これが唯一の連携根拠。`tenant_id` を取らない
/// のは、プロバイダ自体がテナントに属する（＝プロバイダ経由で境界が決まる）ため。
#[async_trait]
pub trait ExternalIdentityRepository: Send + Sync {
    /// 連携を作成する。同じ外部アカウントの二重連携は `Conflict`。
    async fn create(&self, identity: &ExternalIdentity) -> Result<()>;
    /// 検証済みの `iss` + `sub` から連携を引く。
    ///
    /// `provider_id` だけでなく `external_issuer` も条件に含める。管理者はプロバイダの `issuer` を
    /// 後から変更できるため、`provider_id` + `sub` だけで引くと、**別の issuer にある同じ `sub` の
    /// アカウントが、以前連携した利用者に化ける**。連携時の issuer と一致しなければ引けない
    /// （＝未連携として扱う）のが正しい。
    async fn find_by_subject(
        &self,
        provider_id: Uuid,
        external_issuer: &str,
        external_subject: &str,
    ) -> Result<Option<ExternalIdentity>>;
    /// 利用者の全連携を返す（セルフサービスの表示・解除用）。
    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<ExternalIdentity>>;
    /// 利用時刻を記録する。
    async fn touch_last_used(&self, id: Uuid, at: DateTime<Utc>) -> Result<()>;
    /// 連携を解除する（所有者チェック込み）。削除できた場合 `true`。
    async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<bool>;
}

/// 外部 IdP へのリダイレクトからコールバックまでの進行状態（AP10）の永続化。
///
/// `state` は単回使用。消費は「削除できたら勝ち」の原子的なクレームで行う（`saml_sso_requests`
/// と同じ方式。読んでから消すと、同じ `state` の同時提示で両方通る）。
#[async_trait]
pub trait ExternalLoginRequestRepository: Send + Sync {
    async fn create(&self, request: &ExternalLoginRequest) -> Result<()>;
    /// `state` のハッシュで引く（テナント境界込み）。
    async fn find_by_state(
        &self,
        tenant_id: TenantId,
        state_hash: &str,
    ) -> Result<Option<ExternalLoginRequest>>;
    /// 進行状態を削除する。**削除できた場合のみ `true`**（単回使用のクレームを兼ねる）。
    async fn consume(&self, id: Uuid) -> Result<bool>;
    /// 期限切れの進行状態をまとめて削除し、件数を返す（GC）。
    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<u64>;
}

/// 認証器の統合登録簿（AP9。仕様 §5）。
///
/// 種別（TOTP・WebAuthn・リカバリーコード・email OTP）によらず「この利用者が使える認証器」を
/// 1 箇所で答えるためのポート。種別固有の秘密は従来のテーブルが持ち続ける（expand フェーズ）。
/// テナント列を持たない表のため `tenant_id` は取らない（モジュールコメント参照。境界は
/// ユースケース側が `users.tenant_id` 照合で強制する）。
///
/// 参照系・消費系のメソッドは既定実装（「見つからない」）を持つ。テスト用フェイクの記述量を
/// 抑えるためであり、**既定はいずれも fail-closed 側へ倒れる**（見つからない ＝ その認証器では
/// 認証が通らない）。書き込みの `create` だけは既定を持たない（黙って成功すると登録が消える）。
/// 本番の sqlx 実装は全メソッドを上書きする。
#[async_trait]
pub trait UserAuthenticatorRepository: Send + Sync {
    /// 認証器を登録する（`pending` または `active`）。
    async fn create(&self, authenticator: &UserAuthenticator) -> Result<()>;
    /// 内部 ID で引く。
    async fn find_by_id(&self, _id: Uuid) -> Result<Option<UserAuthenticator>> {
        Ok(None)
    }
    /// 利用者の全認証器を新しい順に返す（失効済みを含む。管理・表示用）。
    async fn list_for_user(&self, _user_id: Uuid) -> Result<Vec<UserAuthenticator>> {
        Ok(Vec::new())
    }
    /// 利用者の**使える**認証器（`active` かつ期限内）を種別で絞って返す（ログインのホットパス）。
    /// `authenticator_type` が `None` なら全種別。
    async fn list_usable_for_user(
        &self,
        _user_id: Uuid,
        _authenticator_type: Option<AuthenticatorType>,
        _now: DateTime<Utc>,
    ) -> Result<Vec<UserAuthenticator>> {
        Ok(Vec::new())
    }
    /// 状態を更新する（遷移の可否は Application 層が
    /// [`AuthenticatorStatus::can_transition_to`] で判定してから呼ぶ）。
    /// 対象が無ければ `false`。
    async fn update_status(
        &self,
        _id: Uuid,
        _user_id: Uuid,
        _status: AuthenticatorStatus,
        _at: DateTime<Utc>,
    ) -> Result<bool> {
        Ok(false)
    }
    /// 表示名を更新する。対象が無ければ `false`。
    async fn update_label(&self, _id: Uuid, _user_id: Uuid, _label: &str) -> Result<bool> {
        Ok(false)
    }
    /// 利用時刻を記録する（認証成功時）。
    async fn touch_last_used(&self, _id: Uuid, _at: DateTime<Utc>) -> Result<()> {
        Ok(())
    }
    /// 使い捨て認証器（リカバリーコード・OTP）を**原子的に消費**する。
    ///
    /// `active` かつ期限内の行だけを `revoked` にして返す。すでに使われていた・期限切れ・
    /// 不存在なら `None`。「引いてから状態を見て更新する」方式だと、同じコードを同時に 2 回
    /// 出された場合に両方通ってしまう（authorization code と同じ理由で原子的に行う）。
    async fn consume_single_use(
        &self,
        _user_id: Uuid,
        _authenticator_type: AuthenticatorType,
        _secret_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<Option<UserAuthenticator>> {
        Ok(None)
    }
    /// 指定種別の未失効の行をまとめて失効させ、件数を返す（リカバリーコードの再発行時に
    /// 古い束を無効化する）。
    async fn revoke_all_of_type(
        &self,
        _user_id: Uuid,
        _authenticator_type: AuthenticatorType,
        _at: DateTime<Utc>,
    ) -> Result<u64> {
        Ok(0)
    }
    /// 期限付きの行（＝発行済みのワンタイムコード）だけを失効させ、件数を返す（AP13）。
    ///
    /// [`Self::revoke_all_of_type`] と分けるのは、同じ種別の中に**寿命の無い登録**（SMS OTP の
    /// 登録済み電話番号）と**寿命のあるコード**が混ざるため。新しいコードを出す前に古いコードを
    /// 失効させたいだけなのに `revoke_all_of_type` を使うと、登録そのものが消えてしまう。
    async fn revoke_issued_codes_of_type(
        &self,
        _user_id: Uuid,
        _authenticator_type: AuthenticatorType,
        _at: DateTime<Utc>,
    ) -> Result<u64> {
        Ok(0)
    }
    /// `pending` の行を、提示された秘密（の SHA-256）と突き合わせて**確認済み**にする（AP13）。
    ///
    /// 成功したら `status = active` にし、確認用コードと期限を消す。期限を消すのは、期限付きの
    /// 行が GC（[`ExpiringRecordStore`]）の削除対象だからで、残すと確認済みの登録が消える。
    /// 更新と読み直しを 1 文にするのは、同じコードの同時提示で二重に確認されないため。
    async fn confirm_pending(
        &self,
        _user_id: Uuid,
        _authenticator_type: AuthenticatorType,
        _secret_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<Option<UserAuthenticator>> {
        Ok(None)
    }
    /// 期限切れの使い捨て行を削除し、件数を返す（GC）。
    async fn delete_expired(&self, _now: DateTime<Utc>) -> Result<u64> {
        Ok(0)
    }
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
    /// ユーザーの全クレデンシャルを削除し、削除件数を返す（管理者による MFA 解除。MT21）。
    /// 端末紛失時の復旧手段のため、1 件ずつではなくまとめて消す（消し残しは復旧の失敗になる）。
    async fn delete_all_for_user(&self, user_id: Uuid) -> Result<u64>;
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
    /// 期限切れのチャレンジをまとめて削除し、件数を返す（G2 の一括 GC から呼ぶ）。
    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<u64>;
}

/// 期限切れ行を自分で掃除できるテーブルのポート（G2）。
///
/// 進行状態・使い捨てトークンの表は「期限が来たら意味を失う」が、削除する主体はどのユースケースにも
/// 属さない。表ごとに個別のバックグラウンドループを生やすと、追加のたびに掃除漏れ（＝無限に増える表）が
/// 生まれるため、**掃除できることを 1 つのポートで表明**し、起動時に 1 本のタスクへ束ねる。
///
/// `revoked_access_tokens` のように照合のホットパスに載る表は、肥大がそのままレイテンシになる。
#[async_trait]
pub trait ExpiringRecordStore: Send + Sync {
    /// 掃除対象の識別子（ログに出すテーブル名）。
    fn table_name(&self) -> &'static str;
    /// `now` 時点で期限切れの行を削除し、削除件数を返す。
    async fn purge_expired(&self, now: DateTime<Utc>) -> Result<u64>;
}
