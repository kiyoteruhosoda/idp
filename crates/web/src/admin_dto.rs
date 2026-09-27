//! web が api の JSON 管理 API（`/admin/*`）から受け取るビューモデル（ADR-0007 §4）。
//!
//! これらは api の OpenAPI DTO（`ClientResponse` 等）と同じ JSON 形状を web 側で受けるための
//! 読み取り用構造体。api の管理 API は OpenAPI で公開される契約であり、web はその一消費者として
//! 自前のビューモデルで受ける（内部認証の真の契約は `assay-contracts` に置く）。整合は E2E で検証する。

use serde::Deserialize;

/// クライアント（RP）の公開表現（`GET /admin/clients`・`/admin/clients/{id}` の応答要素）。
#[derive(Debug, Clone, Deserialize)]
pub struct ClientView {
    pub id: String,
    pub client_id: String,
    pub client_type: String,
    pub client_status: String,
    pub app_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    #[allow(dead_code)]
    pub response_types: Vec<String>,
    pub scopes: Vec<String>,
    pub token_endpoint_auth_method: String,
    /// `private_key_jwt` の検証鍵（JWK Set の JSON。ADR-0030）。公開鍵のみ。
    #[serde(default)]
    pub jwks: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// クライアント一覧の 1 ページ分（`GET /admin/clients`。G7）。
#[derive(Debug, Clone, Deserialize)]
pub struct ClientListView {
    pub clients: Vec<ClientView>,
    /// ページング前の総件数。「全 N 件」の表示と次ページの有無に使う。
    pub total: i64,
    /// api が実際に適用した 1 ページの件数（クランプ後）。ページ送りの刻み幅として使う。
    pub limit: i64,
    #[allow(dead_code)]
    pub offset: i64,
}

/// 作成応答（`POST /admin/clients`）。`client_secret` は confidential のときのみ含まれる。
#[derive(Debug, Clone, Deserialize)]
pub struct ClientCreatedView {
    #[serde(flatten)]
    pub client: ClientView,
    #[serde(default)]
    pub client_secret: Option<String>,
}

/// secret 再発行応答（`POST /admin/clients/{id}/secret`）。
#[derive(Debug, Clone, Deserialize)]
pub struct ClientSecretView {
    #[allow(dead_code)]
    pub client_id: String,
    pub client_secret: String,
}

/// 監査ログ 1 行（`GET /admin/audit-logs` の応答要素。設計仕様 §7）。
#[derive(Debug, Clone, Deserialize)]
pub struct AuditLogView {
    #[allow(dead_code)]
    pub id: i64,
    pub event_type: String,
    pub occurred_at: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub user_agent: Option<String>,
    pub result: String,
    #[serde(default)]
    pub reason: Option<String>,
    pub correlation_id: String,
}

/// api のエラー応答本文（`{ "error": code, "message": msg }`）。
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorBody {
    #[allow(dead_code)]
    pub error: String,
    pub message: String,
}

/// 署名鍵の公開表現（`GET /admin/signing-keys` の応答要素）。
#[derive(Debug, Clone, Deserialize)]
pub struct SigningKeyView {
    pub kid: String,
    pub algorithm: String,
    pub status: String,
    pub not_before: String,
    pub not_after: String,
    pub created_at: String,
    /// いま署名に使われている鍵か。**`status` からは読めない** —— ACTIVE は複数あり得て、署名するのは
    /// 1 本だけである。どれかを決める規則は core にあり、web からは引けないので api が判定して返す。
    /// 古い api（この項目を返さない）でも画面を壊さないよう、既定は `false`。
    #[serde(default)]
    pub is_current_signer: bool,
    /// 公開済みだが、まだ署名には使われていない鍵か（`not_before` が未来）。
    #[serde(default)]
    pub is_pending: bool,
}

/// アプリの公開表現（`GET /admin/applications` の応答要素。ADR-0054）。
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationView {
    pub id: String,
    pub display_name: String,
    /// `ACTIVE` / `DISABLED`。
    pub status: String,
    /// `EVERYONE` / `INDIVIDUAL`。
    pub assignment_mode: String,
    #[serde(default)]
    pub bindings: Vec<ApplicationBindingView>,
    #[serde(default)]
    pub assigned_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl ApplicationView {
    /// 使える状態か（テンプレートから状態を文字列比較させないための述語）。
    pub fn is_active(&self) -> bool {
        self.status == "ACTIVE"
    }

    /// 割り当てられた利用者だけが使えるか。
    pub fn is_individual(&self) -> bool {
        self.assignment_mode == "INDIVIDUAL"
    }

    /// ⚠ **誰も入れない状態**（「個別」なのに名簿が空）。
    /// 「全員」と取り違えると全断になるので、一覧で目立たせる。
    pub fn admits_nobody(&self) -> bool {
        self.is_active() && self.is_individual() && self.assigned_count == 0
    }
}

/// 名乗り 1 本の公開表現（ADR-0059）。
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationBindingView {
    pub id: String,
    /// `oidc` / `saml` / `service_account` / `resource`。
    pub kind: String,
    /// ログイン用・サービスアカウントなら `client_id`、SAML なら `entity_id`、宛名なら
    /// `resource_uri`。相手が消えていれば `None`。
    #[serde(default)]
    pub identifier: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

impl ApplicationBindingView {
    /// 種類の表示名の翻訳キー（テンプレートから種類を文字列比較させないため）。
    /// 知らない種類は綴りのまま出す（新しい api と古い web の組み合わせでも画面を壊さない）。
    pub fn kind_label_key(&self) -> &str {
        match self.kind.as_str() {
            "oidc" => "admin-applications-kind-oidc",
            "saml" => "admin-applications-kind-saml",
            "service_account" => "admin-applications-kind-service-account",
            "resource" => "admin-applications-kind-resource",
            other => other,
        }
    }

    /// サービスアカウントの名乗りか（サーバーのアイコンを出す）。
    pub fn is_service_account(&self) -> bool {
        self.kind == "service_account"
    }
}

/// アプリの一覧応答。
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationListView {
    pub applications: Vec<ApplicationView>,
    /// `record_only` / `enforce`。
    #[serde(default)]
    pub enforcement: String,
}

impl ApplicationListView {
    /// 判定がまだ断るところまで来ていないか（＝割り当てが効いていない）。
    pub fn is_record_only(&self) -> bool {
        self.enforcement != "enforce"
    }
}

/// アプリの詳細応答（一覧の 1 件 ＋ 名簿）。
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationDetailView {
    #[serde(flatten)]
    pub application: ApplicationView,
    #[serde(default)]
    pub assigned: Vec<ApplicationAssignmentView>,
    /// 割り当てられたサービスアカウント（ADR-0059）。古い api は返さないので既定は空。
    #[serde(default)]
    pub assigned_service_accounts: Vec<ApplicationServiceAccountAssignmentView>,
    /// `record_only` / `enforce`。
    #[serde(default)]
    pub enforcement: String,
}

impl ApplicationDetailView {
    /// 判定がまだ断るところまで来ていないか（＝割り当てが効いていない）。
    pub fn is_record_only(&self) -> bool {
        self.enforcement != "enforce"
    }
}

/// 割り当てられた利用者 1 行。
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationAssignmentView {
    pub user_id: String,
    pub sub: String,
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    /// 利用者アカウント自体の状態（`ACTIVE` / `DISABLED` / `LOCKED`）。
    pub status: String,
    pub assigned_at: String,
}

impl ApplicationAssignmentView {
    /// 利用者アカウント自体が止まっているか。⚠ 割り当ては残るので、名簿では別に示す。
    pub fn is_user_active(&self) -> bool {
        self.status == "ACTIVE"
    }
}

/// 割り当てられたサービスアカウント 1 行。
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationServiceAccountAssignmentView {
    pub client_id: String,
    pub app_name: String,
    /// クライアントの状態（`ACTIVE` / `DISABLED` / `DELETED`）。
    pub status: String,
    pub assigned_at: String,
}

impl ApplicationServiceAccountAssignmentView {
    /// クライアントが動いているか。⚠ 割り当ては残るので、一覧では別に示す。
    pub fn is_client_active(&self) -> bool {
        self.status == "ACTIVE"
    }
}

/// 「いま入れている人」の応答（「全員」→「個別」へ倒す前の写し元）。
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationCurrentUsersView {
    #[serde(default)]
    pub users: Vec<ApplicationCurrentUserView>,
    #[serde(default)]
    pub total: i64,
    /// ⚠ 真なら「全員は出せていない」。画面がそのまま言うこと。
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationCurrentUserView {
    pub user_id: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// 保護リソース（`aud` に入る宛名）の公開表現（`GET /admin/resources` の応答要素。ADR-0042）。
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceView {
    pub id: String,
    /// トークンの `aud` に入る値そのもの。
    pub resource_uri: String,
    pub display_name: String,
    /// `ACTIVE` / `DISABLED`。
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

impl ResourceView {
    /// 新しいトークンの宛先に使えるか（テンプレートから状態を文字列比較させないための述語）。
    pub fn is_active(&self) -> bool {
        self.status == "ACTIVE"
    }
}

/// 保護リソースの一覧応答。
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceListView {
    pub resources: Vec<ResourceView>,
}

/// SAML SP（クライアント）の公開表現（`GET /admin/saml-service-providers` の応答要素）。
#[derive(Debug, Clone, Deserialize)]
pub struct SamlServiceProviderView {
    pub id: String,
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    /// 署名/暗号証明書（任意）。編集フォームの初期値に使う。
    #[serde(default)]
    pub x509_certificate: Option<String>,
    pub enabled: bool,
}

/// 利用者作成応答（`POST /admin/users`）。本人へ渡すワンタイムリンクが一度限り返る（ADR-0062）。
#[derive(Debug, Clone, Deserialize)]
pub struct UserCreatedView {
    #[allow(dead_code)]
    pub user_id: String,
    #[allow(dead_code)]
    pub sub: String,
    pub setup_url: String,
    pub setup_expires_at: String,
}

/// メンバー一覧の 1 件（`GET /admin/members`。HOME / GUEST を問わない。ADR-0009 §3）。
#[derive(Debug, Clone, Deserialize)]
pub struct MemberView {
    pub user_id: String,
    #[serde(default)]
    pub email: Option<String>,
    /// 主たるログイン識別子（ユーザー名）。api が省略したときは `None`。
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    /// `HOME` または `GUEST`。
    pub membership_type: String,
    /// `INVITED` または `ACTIVE`。
    pub status: String,
    /// 利用者アカウント自体の状態（`ACTIVE` / `DISABLED` / `LOCKED`）。不存在ユーザーは `None`。
    #[serde(default)]
    pub user_status: Option<String>,
    /// ログイン失敗によるロックが今掛かっているか（AP6）。api が期限を判定済みの真偽値で返す
    /// （web は時計を持たないため、期限の比較を web 側でやり直さない）。
    #[serde(default)]
    pub locked: bool,
    /// 仮登録（ADR-0064）。本人がまだ設定リンクで資格情報を決めていない。
    #[serde(default)]
    pub pending_setup: bool,
    /// 仮登録の人の、いまの設定リンクの期限（RFC 3339・UTC）。
    #[serde(default)]
    pub setup_link_expires_at: Option<String>,
    /// 仮登録で、使える設定リンクが無い（期限切れ）。api が読んだ時点で判定した値
    /// （web は時計を持たないので、期限の比較をやり直さない。`locked` と同じ）。
    #[serde(default)]
    pub setup_link_expired: bool,
    /// 管理者メモ（ADR-0063）。書かれていなければ `None`。
    #[serde(default)]
    pub note: Option<AccountNoteView>,
}

impl MemberView {
    /// 一覧の見出しに出す名前（メール → ユーザー名の順に拾う）。
    pub fn headline(&self) -> &str {
        self.email
            .as_deref()
            .or(self.preferred_username.as_deref())
            .unwrap_or("-")
    }

    /// 見出しの下に添える名前。見出しと同じ値は繰り返さない（同じ文字列が 2 段並ぶと読みにくい）。
    pub fn secondary_names(&self) -> Vec<&str> {
        let headline = self.headline();
        let mut out: Vec<&str> = Vec::new();
        for value in [self.preferred_username.as_deref(), self.name.as_deref()]
            .into_iter()
            .flatten()
        {
            if value != headline && !out.contains(&value) {
                out.push(value);
            }
        }
        out
    }
}

/// アカウント（人・サービスアカウント）の管理者メモ（ADR-0063 / ADR-0065）。
#[derive(Debug, Clone, Deserialize)]
pub struct AccountNoteView {
    pub text: String,
    /// RFC 3339（UTC）。画面では `local-time.js` が閲覧者の時刻へ直す。
    pub updated_at: String,
}

impl AccountNoteView {
    /// 一覧に出す 1 行目（長ければ切る）。一覧は探す場所なので、全文は 1 件の画面で読む。
    pub fn excerpt(&self) -> Option<String> {
        const MAX_CHARS: usize = 60;
        let first = self.text.lines().next()?.trim();
        if first.is_empty() {
            return None;
        }
        let mut excerpt: String = first.chars().take(MAX_CHARS).collect();
        if first.chars().count() > MAX_CHARS || self.text.contains('\n') {
            excerpt.push('…');
        }
        Some(excerpt)
    }
}

/// サービスアカウント 1 件（`GET /admin/service-accounts/{client_id}`・一覧の 1 行。ADR-0065）。
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceAccountView {
    pub client_id: String,
    pub app_name: String,
    /// `ACTIVE` / `DISABLED`。
    pub status: String,
    /// RFC 3339（UTC）。
    pub created_at: String,
    /// このサービスアカウントを名乗り（binding）に持つアプリ。
    #[serde(default)]
    pub identity_of: Option<IdentityApplicationView>,
    #[serde(default)]
    pub note: Option<AccountNoteView>,
}

/// サービスアカウントを名乗りに持つアプリ。
#[derive(Debug, Clone, Deserialize)]
pub struct IdentityApplicationView {
    pub application_id: String,
    pub display_name: String,
}

/// アカウント一覧の 1 行（`kind` に応じて `user` / `service_account` のどちらかが載る。ADR-0065）。
#[derive(Debug, Clone, Deserialize)]
pub struct AccountView {
    /// `user` / `service_account`。
    pub kind: String,
    #[serde(default)]
    pub user: Option<MemberView>,
    #[serde(default)]
    pub service_account: Option<ServiceAccountView>,
}

impl AccountView {
    /// 1 件の画面へのパス（テナントの前置きを除く）。種別ごとに経路が違う。
    pub fn path(&self) -> String {
        match (&self.user, &self.service_account) {
            (Some(m), _) => format!("/admin/members/{}", m.user_id),
            (None, Some(sa)) => format!("/admin/service-accounts/{}", sa.client_id),
            (None, None) => "/admin/accounts".to_string(),
        }
    }

    /// 見出し（人はメール → ユーザー名、サービスアカウントは登録名）。
    pub fn headline(&self) -> &str {
        match (&self.user, &self.service_account) {
            (Some(m), _) => m.headline(),
            (None, Some(sa)) => &sa.app_name,
            (None, None) => "-",
        }
    }

    /// 見出しの下に添える名前（人はユーザー名・氏名、サービスアカウントは `client_id`）。
    pub fn secondary_names(&self) -> Vec<&str> {
        match (&self.user, &self.service_account) {
            (Some(m), _) => m.secondary_names(),
            (None, Some(sa)) => vec![sa.client_id.as_str()],
            (None, None) => Vec::new(),
        }
    }

    /// 一覧に出すメモの 1 行目。
    pub fn note_excerpt(&self) -> Option<String> {
        match (&self.user, &self.service_account) {
            (Some(m), _) => m.note.as_ref()?.excerpt(),
            (None, Some(sa)) => sa.note.as_ref()?.excerpt(),
            (None, None) => None,
        }
    }
}

/// アカウント一覧の 1 ページ分（`GET /admin/accounts`。ADR-0065）。
#[derive(Debug, Clone, Deserialize)]
pub struct AccountListView {
    pub accounts: Vec<AccountView>,
    /// 実際に並べた種別。
    #[allow(dead_code)]
    pub kinds: Vec<String>,
    /// 読める種別（絞り込みの選択肢）。
    pub readable_kinds: Vec<String>,
    /// 絞り込み後の総件数（ページング前）。
    pub total: i64,
    /// api が実際に適用した 1 ページの件数（クランプ後）。
    pub limit: i64,
    #[allow(dead_code)]
    pub offset: i64,
}

/// アカウント 1 つが使えるアプリ（`GET /admin/members/{user_id}/applications`・
/// `GET /admin/service-accounts/{client_id}/applications`。ADR-0063 / ADR-0065）。
#[derive(Debug, Clone, Deserialize)]
pub struct AccountApplicationListView {
    pub applications: Vec<AccountApplicationView>,
    /// `record_only` / `enforce`。
    pub enforcement: String,
}

impl AccountApplicationListView {
    /// 可否ごとの件数（絞り込みの札に添える）。
    pub fn count(&self, access: &str) -> usize {
        self.applications
            .iter()
            .filter(|a| a.access == access)
            .count()
    }
}

/// アカウントから見たアプリ 1 件。
#[derive(Debug, Clone, Deserialize)]
pub struct AccountApplicationView {
    pub application_id: String,
    pub display_name: String,
    /// `ACTIVE` / `DISABLED`。
    pub status: String,
    /// `EVERYONE` / `INDIVIDUAL`。
    pub assignment_mode: String,
    /// `allowed` / `not_assigned` / `application_disabled`。
    pub access: String,
    #[serde(default)]
    pub assigned_at: Option<String>,
}

/// 管理者によるパスワード再発行応答（`POST /admin/users/{id}/password-reset` ほか）。
/// 本人へ渡すワンタイムリンクが一度限り返る（ADR-0062）。
///
#[derive(Debug, Clone, Deserialize)]
pub struct UserPasswordResetView {
    #[allow(dead_code)]
    pub user_id: String,
    pub setup_url: String,
    pub setup_expires_at: String,
}

/// 管理者による MFA 解除の結果（`POST /admin/users/{id}/mfa-reset`。MT21）。
/// 何を外したかだけが返る（シークレット・クレデンシャルは含まれない）。
#[derive(Debug, Clone, Deserialize)]
pub struct UserMfaResetView {
    #[allow(dead_code)]
    pub user_id: String,
    pub totp_removed: bool,
    pub passkeys_removed: u64,
}

/// 管理者によるトークン再発行の結果（`POST /admin/users/{id}/token-reissue`。ADR-0047）。
/// `revoked` で「落とした」と「対象が無かった」を出し分ける。
#[derive(Debug, Clone, Deserialize)]
pub struct UserTokenReissueView {
    #[allow(dead_code)]
    pub user_id: String,
    pub revoked: u64,
}

/// 管理者によるアカウントロック解除の結果（`POST /admin/users/{id}/unlock`。AP6）。
/// `was_locked` で「解除した」と「元からロックされていない」を出し分ける。
#[derive(Debug, Clone, Deserialize)]
pub struct UserUnlockView {
    #[allow(dead_code)]
    pub user_id: String,
    pub was_locked: bool,
}

/// 招待作成応答（`POST /admin/invitations`）。`token` は一度限り平文で返る（ADR-0009 §3）。
#[derive(Debug, Clone, Deserialize)]
pub struct InvitationCreatedView {
    pub token: String,
    pub expires_at: String,
    /// 招待メール（承諾リンク）を送信できたか（MT17）。false なら手動でトークンを伝達する。
    pub email_sent: bool,
    /// 被招待者のメールアドレス（送信先の確認表示用）。
    pub invitee_email: String,
}

/// テナントの公開表現（`GET/PATCH /admin/settings/tenant` の応答。MT14）。
#[derive(Debug, Clone, Deserialize)]
pub struct TenantView {
    pub id: String,
    pub name: String,
    /// 自己登録（`/auth/register`）を許可するか（SEC6。既定は無効）。
    #[serde(default)]
    pub self_registration_enabled: bool,
    /// メールアドレスでのログインを許可するか（ADR-0050。既定は無効）。
    #[serde(default)]
    pub email_login_enabled: bool,
    /// `ACTIVE` または `DISABLED`。
    pub status: String,
}

/// 子テナント一覧の 1 ページ分（`GET /admin/tenants`。G7）。
#[derive(Debug, Clone, Deserialize)]
pub struct TenantListView {
    pub tenants: Vec<TenantView>,
    /// ページング前の総件数。
    pub total: i64,
    /// api が実際に適用した 1 ページの件数（クランプ後）。
    pub limit: i64,
    #[allow(dead_code)]
    pub offset: i64,
}

/// テナント作成応答（`POST /admin/tenants`）。作成者自身がブートストラップ管理者になるため、
/// 初期管理者 ID・平文パスワードは含まない（作成したテナントそのものを返す。ADR-0009 §4）。
#[derive(Debug, Clone, Deserialize)]
pub struct TenantCreatedView {
    pub id: String,
    #[serde(default)]
    pub parent_tenant_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub self_registration_enabled: bool,
    pub status: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

/// システム設定の公開表現（`GET/PUT /admin/system-settings` の応答。MT14）。
/// SMTP パスワードは平文を含まず、設定済みか否か（`smtp_password_set`）のみ。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeSettingView {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub secret: bool,
    #[serde(default)]
    pub restart_required: bool,
    #[serde(default)]
    pub default_risk: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub reason: String,
    /// この設定が何に使われるかの説明（運用者向け）。
    #[serde(default)]
    pub description: String,
    /// 起動時に解決された有効値（非 secret のみ）。DB 更新後も再起動までは変わらない。
    #[serde(default)]
    pub value: Option<String>,
    /// 組み込み既定値（非 secret のみ）。
    #[serde(default)]
    pub default_value: Option<String>,
    /// 現在 DB に保存されている上書き値（非 secret のみ）。
    #[serde(default)]
    pub db_value: Option<String>,
    /// この画面（DB）から上書きできるか（`DB_MANAGED` かつ非 secret）。
    #[serde(default)]
    pub editable: bool,
    /// 保存済みだが実行中の api へ未反映か（MT27）。上書きの解除が未反映の場合も `true`。
    #[serde(default)]
    pub pending_restart: bool,
    /// web も消費するキーか（ADR-0013）。反映に api と web の両方の再起動が要る。
    #[serde(default)]
    pub shared_with_web: bool,
    /// テナントが上書きできるキーか（ADR-0058）。
    #[serde(default)]
    pub tenant_overridable: bool,
    /// 全体の値に従っているテナントの件数（テナントが上書きできるキーのみ）。
    #[serde(default)]
    pub tenants_following: Option<u64>,
    /// 既定から外れているテナント（テナントが上書きできるキーのみ）。
    #[serde(default)]
    pub tenants_overriding: Vec<TenantOverrideView>,
}

/// 全体の設定画面に出す「既定から外れているテナント」1 件（ADR-0058 §6）。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TenantOverrideView {
    pub tenant_id: String,
    pub tenant_name: String,
    pub value: String,
}

/// テナント自身のメールの経路（`GET/PUT/DELETE /admin/settings/smtp`。ADR-0058 §8）。
///
/// `inherited` が true のときは全体の経路で送られている。⚠ そのとき api は項目を空で返す
/// （全体の宛先・利用者名はテナントへ見せない）。パスワードは設定の有無だけ。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TenantSmtpView {
    #[serde(default)]
    pub inherited: bool,
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: Option<u16>,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password_set: bool,
    #[serde(default)]
    pub smtp_from_address: String,
    #[serde(default)]
    pub smtp_use_tls: bool,
}

/// テナントの設定値の一覧（`GET /admin/settings/tenant/keys`。ADR-0058）。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TenantSettingsListView {
    #[serde(default)]
    pub settings: Vec<TenantSettingView>,
}

/// テナントの設定 1 項目。項目の並びも入力欄の形も api が返す定義から決める（web は項目を知らない）。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TenantSettingView {
    pub key: String,
    #[serde(default)]
    pub description: String,
    /// `UNSIGNED_INTEGER` / `BOOLEAN` / `TEXT` / `PUBLIC_BASE_URL` / `CHOICE`。
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub choices: Vec<SettingChoiceView>,
    #[serde(default)]
    pub value: String,
    /// `TENANT_OVERRIDE`（このテナントで決めた）/ `INHERITED`（全体に従っている）。
    #[serde(default)]
    pub origin: String,
    /// 全体の値（上書きを消すとこの値に戻る）。
    #[serde(default)]
    pub whole_idp_value: String,
}

impl TenantSettingView {
    /// このテナントで決めた値か（`false` = 全体に従っている）。
    pub fn is_tenant_override(&self) -> bool {
        self.origin == "TENANT_OVERRIDE"
    }
}

/// 選択肢 1 つ。`locks_out` の値へ変えるときは保存の前に確認を挟む。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SettingChoiceView {
    pub value: String,
    #[serde(default)]
    pub locks_out: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SystemSettingsView {
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: Option<u16>,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password_set: bool,
    #[serde(default)]
    pub smtp_from_address: String,
    #[serde(default)]
    pub smtp_use_tls: bool,
    /// SMS ゲートウェイ（AP13）。トークンは平文を含まず、設定済みか否か（`sms_auth_token_set`）のみ。
    #[serde(default)]
    pub sms_gateway_url: String,
    #[serde(default)]
    pub sms_auth_header: String,
    #[serde(default)]
    pub sms_auth_token_set: bool,
    #[serde(default)]
    pub sms_sender_id: String,
    #[serde(default)]
    pub runtime_settings: Vec<RuntimeSettingView>,
}

// ── 外部 IdP 設定（AP10 の API を AP16 で画面化する）─────────────────────────────

/// 外部 IdP 設定の 1 件（`GET /admin/external-idps`）。
///
/// `client_secret` は api が返さない（保存は暗号化、復号は外部 IdP へトークン要求を出す瞬間だけ）。
/// 画面は「設定済みかどうか」（`has_client_secret`）だけを出す。
///
/// プロトコル固有の項目（OIDC のエンドポイント・SAML の SSO URL）は api では**使わない側が
/// `null`** になる（ADR-0027）。`Option` で受けないと、SAML のプロバイダが 1 件でも登録された
/// 時点で一覧の解析ごと失敗し、画面が開かなくなる。
#[derive(Debug, Clone, Deserialize)]
pub struct ExternalIdpView {
    pub id: String,
    pub provider_code: String,
    pub display_name: String,
    pub issuer: String,
    /// `oidc` / `saml`。
    #[serde(default = "oidc_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    pub has_client_secret: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// SAML のみ。
    #[serde(default)]
    pub saml_sso_url: Option<String>,
    #[serde(default)]
    pub saml_certificates: Vec<String>,
    #[serde(default)]
    pub saml_name_id_format: Option<String>,
    /// SAML のみ。外部 IdP 側へ登録すべき assay の entityID と ACS URL。
    #[serde(default)]
    pub saml_sp_entity_id: Option<String>,
    #[serde(default)]
    pub saml_acs_url: Option<String>,
    pub enabled: bool,
    pub allow_auto_link: bool,
    /// 外部 IdP 側へ登録すべきコールバック URL（設定作業の手掛かり）。
    pub redirect_uri: String,
    #[allow(dead_code)]
    pub created_at: String,
    #[allow(dead_code)]
    pub updated_at: String,
}

fn oidc_protocol() -> String {
    "oidc".to_string()
}

impl ExternalIdpView {
    pub fn is_saml(&self) -> bool {
        self.protocol == "saml"
    }

    /// 外部 IdP 側へ登録してもらう受け口の URL。OIDC は `redirect_uri`、SAML は ACS URL で、
    /// 一覧では同じ列に出す（管理者にとっては「相手に貼る URL」という同じ役割）。
    pub fn callback_url(&self) -> &str {
        match self.saml_acs_url.as_deref() {
            Some(acs) if self.is_saml() => acs,
            _ => &self.redirect_uri,
        }
    }
}

// ── ログイン識別子（AP8 の API を AP16 で画面化する）───────────────────────────

/// 利用者のログイン識別子 1 件（`GET /admin/users/{id}/login-identifiers`）。
#[derive(Debug, Clone, Deserialize)]
pub struct LoginIdentifierView {
    /// 登録簿の行 id。`None` は主たる識別子（`users.preferred_username`）を合成した行で、
    /// 保存されていないため識別子単位の操作ができない。
    pub id: Option<String>,
    pub identifier_type: String,
    /// 登録されたままの値（表示用）。
    pub display_value: String,
    /// 照合キー（種別ごとの正規化を適用した値）。**両方出す**のが要点で、管理者が
    /// 「登録した値」と「実際に一致する値」を突き合わせられないと、電話番号のように
    /// 書き方が揺れる識別子の設定ミスに気づけない。
    pub normalized_value: String,
    pub is_active: bool,
    pub is_primary: bool,
    /// 主メールアドレスの行か（ADR-0050）。個別の有効/無効・削除の対象にならない。
    #[serde(default)]
    pub is_primary_email: bool,
    #[allow(dead_code)]
    pub created_at: String,
    #[allow(dead_code)]
    pub updated_at: String,
}
