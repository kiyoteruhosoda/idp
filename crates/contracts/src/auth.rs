//! 内部認証 API（`/internal/authenticate*`、ADR-0007 §3）の DTO 契約。
//!
//! web（ログイン画面）→api の内部認証呼び出しで共有する。web が [`InternalAuthenticateRequest`] /
//! [`InternalAdminAuthenticateRequest`] を送信（serialize）し、api が受信（deserialize）する。応答は
//! `result` タグで判別し、成功時のみ SSO/redirect 情報を含む。Cookie 組み立て（Secure/HttpOnly/
//! SameSite/TTL）とエラー文言のローカライズは呼び出し側（web）が担う。
//!
//! `/internal/*` は外部公開しない内部 I/F のため OpenAPI（`utoipa::ToSchema`）には含めない。

use serde::{Deserialize, Serialize};

/// 内部認証 API（`POST /internal/authenticate`）のリクエスト。
///
/// web が資格情報・`auth_session_id` 参照・接続元情報（`X-Forwarded-For` 由来 IP・User-Agent）を
/// api へ転送する。CSRF は `csrf_token`（`auth_session_id` 由来）を api の LoginService が検証する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAuthenticateRequest {
    /// フローのテナント（ADR-0009 §8）。`(tenant_id, email)` 一意化により、認証は所属元テナント限定。
    /// **必須**。api は未指定・不正な UUID を 400 で拒否する（fail-closed。SEC4）。
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub auth_session_id: Option<String>,
    /// ログイン識別子はメールアドレスに統一する（ADR-0009 §8。`(tenant_id, email)` 一意化）。
    pub email: String,
    pub password: String,
    pub csrf_token: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 内部認証 API のレスポンス。`result` タグで判別する。成功時のみ SSO/redirect 情報を返す。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAuthenticateResponse {
    /// 認証成功かつ同意済み。`redirect_to`（code 付き RP URL）へ 302 し、`sso_session_id` を Cookie 化する。
    Success {
        redirect_to: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
        /// ユーザーの表示言語設定（`ja` / `en`。MT20）。None = 未設定。
        /// web は `lang` Cookie をこの値で上書きし、優先度2（ユーザー設定）を実現する。
        #[serde(default)]
        user_language: Option<String>,
    },
    /// 認証成功だが同意が必要。`auth_session_id` Cookie を発行して `/consent` へ 302 する。
    /// `sso_session_id` も発行する（SSO Cookie をセットするため）。
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// パスワード認証成功だが MFA（TOTP）が設定済み。TOTP 入力画面 `/mfa/totp` へ誘導する。
    /// `auth_session_id` Cookie はそのまま維持する（MFA 検証で使う）。
    MfaRequired { auth_session_id: String },
    /// パスワード認証成功だが `must_change_password`（ADR-0009 §5）。パスワード変更画面へ誘導する。
    /// `auth_session_id` Cookie はそのまま維持する（変更処理で使う）。
    PasswordChangeRequired { auth_session_id: String },
    /// パスワード認証成功だが自己登録アカウントのメール未検証（SEC6b）。確認リンクを踏むまで
    /// ログインを許可しない。web は「メールを確認して」の案内を表示する。
    EmailVerificationRequired,
    /// AuthSession が無い・期限切れ（`/authorize` からやり直し）。
    SessionExpired,
    /// CSRF トークン不一致。
    CsrfMismatch,
    /// IP 単位のレート制限超過。
    RateLimited,
    /// 資格情報不正。
    InvalidCredentials,
    /// アカウントロック中。
    Locked,
    /// api 内部エラー。
    Internal,
}

/// TOTP セットアップ開始 API（`POST /internal/mfa/totp/setup`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalTotpSetupRequest {
    /// SSO セッション Cookie の生値（web が転送）。
    pub sso_session_id: String,
    /// 認証アプリに表示するアカウント名（通常はメールアドレスまたはユーザー名）。
    pub account_name: String,
}

/// TOTP セットアップ開始 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalTotpSetupResponse {
    /// セットアップ開始成功。QR URI と生シークレット（base32）を返す。
    Ok {
        /// `otpauth://totp/...` URI。QR コード生成に使う。
        totp_uri: String,
        /// base32 エンコードされたシークレット。QR が使えないユーザーへ直接表示する。
        secret_base32: String,
    },
    /// すでに有効な TOTP が設定済み（再セットアップ不可。先に削除が必要）。
    AlreadyConfigured,
    /// SSO セッションが無い・期限切れ。
    SessionExpired,
    /// api 内部エラー。
    Internal,
}

/// TOTP 確認 API（`POST /internal/mfa/totp/confirm`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalTotpConfirmRequest {
    pub sso_session_id: String,
    /// ユーザーが認証アプリから入力した 6 桁コード。
    pub code: String,
}

/// TOTP 確認 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalTotpConfirmResponse {
    Ok,
    InvalidCode,
    NotFound,
    AlreadyConfigured,
    SessionExpired,
    Internal,
}

/// TOTP 削除 API（`POST /internal/mfa/totp/delete`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalTotpDeleteRequest {
    pub sso_session_id: String,
}

/// TOTP 削除 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalTotpDeleteResponse {
    Ok,
    SessionExpired,
    Internal,
}

/// ログイン TOTP 検証 API（`POST /internal/mfa/totp/verify`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalVerifyTotpRequest {
    /// フローのテナント（ADR-0009 §8）。**必須**。api は未指定・不正な UUID を 400 で拒否する（fail-closed。SEC4）。
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub auth_session_id: Option<String>,
    pub totp_code: String,
    pub csrf_token: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// ログイン TOTP 検証 API のレスポンス。成功系は `InternalAuthenticateResponse` と同等。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalVerifyTotpResponse {
    Success {
        redirect_to: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
        /// ユーザーの表示言語設定（MT20）。web は `lang` Cookie をこの値で上書きする。
        #[serde(default)]
        user_language: Option<String>,
    },
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    SessionExpired,
    CsrfMismatch,
    InvalidCode,
    Internal,
}

/// パスワード変更 API（`POST /internal/change-password`、ADR-0009 §5）のリクエスト。
///
/// `LoginService` が検出した `must_change_password` を受けて、ログイン中の `auth_session_id`
/// （パスワード検証済み状態）で新パスワードを設定する。「ログイン済みユーザーが現行パスワードで
/// 認証したうえで新パスワードを設定する」フローのため、現行パスワードを含める。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalChangePasswordRequest {
    /// フローのテナント（ADR-0009 §8）。**必須**。api は未指定・不正な UUID を 400 で拒否する（fail-closed。SEC4）。
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub auth_session_id: Option<String>,
    pub current_password: String,
    pub new_password: String,
    pub csrf_token: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// パスワード変更 API のレスポンス。成功系は `InternalAuthenticateResponse` と同等。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalChangePasswordResponse {
    Success {
        redirect_to: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    SessionExpired,
    CsrfMismatch,
    /// 現行パスワードが不一致。
    InvalidCurrentPassword,
    /// 新パスワードが強度要件（最低文字数等）を満たさない。
    WeakPassword,
    Internal,
}

/// セルフサービスのパスワード変更 API（`POST /internal/account/change-password`、MT15）のリクエスト。
///
/// ログインフロー中の強制変更（[`InternalChangePasswordRequest`]、`auth_session` ベース）とは別に、
/// **SSO セッションを持つログイン済みユーザー**が設定画面から自分のパスワードを変更する経路。
/// web が SSO Cookie の生値を転送し、api が本人を解決して現行パスワードを再検証する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountChangePasswordRequest {
    /// SSO セッション Cookie の生値。
    pub sso_session_id: String,
    pub current_password: String,
    pub new_password: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// セルフサービスのパスワード変更 API のレスポンス。OIDC フローではないため redirect/code は返さない。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountChangePasswordResponse {
    Ok,
    /// SSO セッションが無い・期限切れ（未ログイン扱い）。
    SessionExpired,
    /// 現行パスワードが不一致。
    InvalidCurrentPassword,
    /// 新パスワードが強度要件を満たさない。
    WeakPassword,
    Internal,
}

/// パスワードリセット要求 API（`POST /internal/password-reset/request`。MT18）のリクエスト。
/// 未ログイン経路のため SSO は不要。web の CSRF はフォームセッション非依存のため api では検証しない。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPasswordResetRequestRequest {
    /// ログイン画面のテナント（ADR-0009 §8）。**必須**。api は未指定・不正な UUID を 400 で拒否する。
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub email: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// パスワードリセット要求 API のレスポンス。アカウントの有無では分岐しない（列挙防止。MT18）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPasswordResetRequestResponse {
    /// 受理（アカウントが存在すればメールを送った）。
    Accepted,
    /// SMTP 未設定で機能自体が利用できない（アカウント非依存）。
    Unavailable,
    RateLimited,
}

/// パスワードリセット実行 API（`POST /internal/password-reset/complete`。MT18）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPasswordResetCompleteRequest {
    /// リセット画面のテナント。**必須**（トークン所有者の所属元と一致しないと失敗する）。
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// メールのリンクで受け取った平文トークン。
    pub token: String,
    pub new_password: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// パスワードリセット実行 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPasswordResetCompleteResponse {
    Ok,
    /// トークンが無効・期限切れ・使用済み・別テナント。
    InvalidOrExpired,
    WeakPassword,
    Internal,
}

/// 管理コンソール内部認証 API（`POST /internal/authenticate/admin`、ADR-0007 §3・§4）のリクエスト。
///
/// 管理ログインの CSRF は web 側で検証済み（ADR-0007 §4）のため本 API には含めない。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAdminAuthenticateRequest {
    /// 管理ログインのテナント（ADR-0009 §8）。**必須**。api は未指定・不正な UUID を 400 で拒否する（fail-closed。SEC4）。
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// ログイン識別子はメールアドレスに統一する（ADR-0009 §8）。
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 内部ログアウト API（`POST /internal/logout`、ADR-0007）のリクエスト。
///
/// web が管理コンソールのログアウトで、失効させたい SSO セッション id（Cookie 値）と接続元情報を転送する。
/// Cookie の失効は web が行い、api は DB のセッション削除と監査記録を担う。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalLogoutRequest {
    /// ログアウト対象フローのテナント（ADR-0009 §8）。**必須**。api は未指定・不正な UUID を 400 で拒否する（fail-closed。SEC4）。
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 管理コンソール内部認証 API のレスポンス。成功時は SSO セッション id を返す（code/redirect は無い）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAdminAuthenticateResponse {
    /// 認証成功かつ `idp.tenant.admin` 保有。`sso_session_id` を Cookie 化して管理コンソールへ 302 する。
    Success {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// IP 単位のレート制限超過。
    RateLimited,
    /// 資格情報不正。
    InvalidCredentials,
    /// アカウントロック中。
    Locked,
    /// 資格情報は正しいが テナント admin 権限を保有しない。
    Forbidden,
    /// 認証成功・管理権限保有だが `must_change_password`（ADR-0009 §5）。パスワード変更画面へ誘導する。
    /// `email` はフォーム再表示用に入力値をそのまま返す。SSO はまだ発行しない。
    PasswordChangeRequired { email: String },
    /// api 内部エラー。
    Internal,
}

/// 管理コンソールの強制パスワード変更 API（`POST /internal/authenticate/admin/change-password`、
/// ADR-0009 §5）のリクエスト。管理ログインは `auth_session_id` のような一時状態を持たないため、
/// 現行パスワードを含めフルに再検証する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAdminChangePasswordRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// ログイン識別子はメールアドレスに統一する（ADR-0009 §8）。
    pub email: String,
    pub current_password: String,
    pub new_password: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 管理コンソールの強制パスワード変更 API のレスポンス。成功時は `InternalAdminAuthenticateResponse`
/// と同等（SSO セッション id を返す）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAdminChangePasswordResponse {
    Success {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    RateLimited,
    InvalidCredentials,
    Locked,
    Forbidden,
    WeakPassword,
    Internal,
}

/// エンドユーザー・ポータル内部認証 API（`POST /internal/authenticate/portal`）のリクエスト。
///
/// 管理コンソールの [`InternalAdminAuthenticateRequest`] と同形。ポータルは OIDC クライアント（RP）を
/// 介さず IdP 自身のアカウント画面（`/{tenant_id}/settings`）へ入るための直接ログインで、成功時は
/// authorization code を発行せず SSO セッションを直接発行する。CSRF は web 側で検証済み。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPortalAuthenticateRequest {
    /// ログインのテナント（ADR-0009 §8）。**必須**。api は未指定・不正な UUID を 400 で拒否する。
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// ログイン識別子はメールアドレスに統一する（ADR-0009 §8）。
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// ポータル内部認証 API のレスポンス。成功時は SSO セッション id を返す（code/redirect は無い）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPortalAuthenticateResponse {
    /// 認証成功（TOTP 未設定）。`sso_session_id` を Cookie 化してアカウント画面へ 302 する。
    Success {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
        #[serde(default)]
        user_language: Option<String>,
    },
    /// パスワード認証成功だが TOTP が必要。`mfa_ticket` は署名付きの短命チケット（user_id ＋ 期限）で、
    /// web はこれを Cookie 化して TOTP 入力画面へ誘導する。SSO はまだ発行しない。
    MfaRequired { mfa_ticket: String },
    /// 自己登録アカウントのメール未検証（SEC6b）。確認リンクを踏むよう案内する。
    EmailVerificationRequired,
    /// 強制パスワード変更が必要（ADR-0009 §5）。web は強制パスワード変更フォームへ誘導する
    /// （管理コンソールと同方式。`email` は入力値をフォーム再表示用にそのまま返す）。
    PasswordChangeRequired { email: String },
    /// IP 単位のレート制限超過。
    RateLimited,
    /// 資格情報不正。
    InvalidCredentials,
    /// アカウントロック中。
    Locked,
    /// api 内部エラー。
    Internal,
}

/// ポータルの強制パスワード変更 API（`POST /internal/authenticate/portal/change-password`、
/// ADR-0009 §5）のリクエスト。ポータルログインは `auth_session_id` のような一時状態を持たないため、
/// 管理コンソールと同じく現行パスワードを含めフルに再検証する（admin 権限は要求しない）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPortalChangePasswordRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// ログイン識別子（メールアドレス）。
    pub email: String,
    pub current_password: String,
    pub new_password: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// ポータルの強制パスワード変更 API のレスポンス。成功時は SSO セッション id を返す
/// （`InternalPortalAuthenticateResponse::Success` と同様に code/redirect は無い）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPortalChangePasswordResponse {
    Success {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
        #[serde(default)]
        user_language: Option<String>,
    },
    /// パスワード変更成功だが TOTP が必要（`login()` と同じ MFA ゲート）。`mfa_ticket` を Cookie 化して
    /// TOTP 入力画面へ誘導する。SSO はまだ発行しない。
    MfaRequired {
        mfa_ticket: String,
    },
    /// 自己登録アカウントのメール未検証（SEC6b）。確認リンクを踏むよう案内する。
    EmailVerificationRequired,
    RateLimited,
    /// 資格情報不正（利用者不存在・現行パスワード不一致・無効アカウント等を区別しない）。
    InvalidCredentials,
    Locked,
    /// 新パスワードが強度要件を満たさない。
    WeakPassword,
    Internal,
}

/// ポータルの TOTP 検証 API（`POST /internal/authenticate/portal/mfa`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPortalMfaRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// [`InternalPortalAuthenticateResponse::MfaRequired`] で返した署名付きチケット。
    pub mfa_ticket: String,
    pub totp_code: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// ポータルの TOTP 検証 API のレスポンス。成功時は SSO セッション id を返す。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPortalMfaResponse {
    Success {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
        #[serde(default)]
        user_language: Option<String>,
    },
    /// TOTP コード不正（チケットが有効なら再試行できる）。
    InvalidCode,
    /// チケットが無効・期限切れ（ログインからやり直し）。
    TicketExpired,
    /// IP 単位のレート制限超過。
    RateLimited,
    /// api 内部エラー。
    Internal,
}

/// 同意画面情報 API（`GET /internal/consent-info`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalConsentInfoRequest {
    /// フローのテナント（ADR-0009 §8）。**必須**。api は未指定・不正な UUID を 400 で拒否する（fail-closed。SEC4）。
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub auth_session_id: String,
}

/// 同意画面情報 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalConsentInfoResponse {
    /// セッションが有効。同意画面に必要な情報を返す。
    Ok {
        auth_session_id: String,
        client_name: String,
        client_id: String,
        /// 同意を求めるスコープ（`openid` は除く）。
        requested_scopes: Vec<String>,
    },
    /// AuthSession が無い・期限切れ・認証済みユーザー未設定（`/authorize` からやり直し）。
    SessionExpired,
}

/// 同意承認 API（`POST /internal/consent/approve`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalConsentApproveRequest {
    /// フローのテナント（ADR-0009 §8）。**必須**。api は未指定・不正な UUID を 400 で拒否する（fail-closed。SEC4）。
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub auth_session_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 同意承認 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalConsentApproveResponse {
    /// 同意付与・code 発行成功。`redirect_to`（code 付き RP URL）へ 302 する。
    Success { redirect_to: String },
    /// AuthSession が無い・期限切れ。
    SessionExpired,
    /// api 内部エラー。
    Internal,
}

/// 同意拒否 API（`POST /internal/consent/deny`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalConsentDenyRequest {
    /// フローのテナント（ADR-0009 §8）。**必須**。api は未指定・不正な UUID を 400 で拒否する（fail-closed。SEC4）。
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub auth_session_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 同意拒否 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalConsentDenyResponse {
    /// 拒否処理完了。`redirect_to`（`access_denied` エラー付き RP URL）へ 302 する。
    Ok { redirect_to: String },
    /// AuthSession が無い・期限切れ（RP へのリダイレクトができない）。
    SessionExpired,
    /// api 内部エラー。
    Internal,
}

// ─── Passkey（WebAuthn）登録 API ─────────────────────────────────────────────

/// Passkey 登録開始 API（`POST /internal/passkey/register/begin`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPasskeyRegisterBeginRequest {
    /// SSO セッション Cookie の生値。
    pub sso_session_id: String,
    /// 認証器に表示するユーザー名（通常は email）。
    pub user_name: String,
}

/// Passkey 登録開始 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPasskeyRegisterBeginResponse {
    /// 開始成功。`challenge_id` を complete で使う。`options` を JS WebAuthn API に渡す。
    Ok {
        challenge_id: String,
        options: serde_json::Value,
    },
    /// SSO セッションが無い・期限切れ。
    SessionExpired,
    /// api 内部エラー。
    Internal,
}

/// Passkey 登録完了 API（`POST /internal/passkey/register/complete`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPasskeyRegisterCompleteRequest {
    pub sso_session_id: String,
    pub challenge_id: String,
    /// ユーザーが付けたデバイス名（例: "MacBook Touch ID"）。
    pub name: String,
    /// ブラウザの `navigator.credentials.create()` が返したオブジェクト（JSON）。
    pub credential: serde_json::Value,
}

/// Passkey 登録完了 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPasskeyRegisterCompleteResponse {
    /// 登録成功。`credential_id` は管理画面表示用。
    Ok { credential_id: String },
    /// チャレンジが見つからない・期限切れ。
    ChallengeNotFound,
    /// クレデンシャルが無効。
    InvalidCredential,
    /// 同一デバイスが既に登録済み。
    DuplicateCredential,
    /// SSO セッションが無い・期限切れ。
    SessionExpired,
    /// api 内部エラー。
    Internal,
}

/// Passkey 削除 API（`POST /internal/passkey/delete`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPasskeyDeleteRequest {
    pub sso_session_id: String,
    /// 削除対象の内部 UUID（`InternalPasskeyRegisterCompleteResponse::Ok.credential_id`）。
    pub credential_id: String,
}

/// Passkey 削除 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPasskeyDeleteResponse {
    Ok,
    SessionExpired,
    Internal,
}

/// Passkey 一覧 API（`POST /internal/passkey/list`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPasskeyListRequest {
    pub sso_session_id: String,
}

/// 登録済みクレデンシャルの概要。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredentialInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// Passkey 一覧 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPasskeyListResponse {
    Ok {
        credentials: Vec<PasskeyCredentialInfo>,
    },
    SessionExpired,
    Internal,
}

// ─── Passkey（WebAuthn）認証 API ─────────────────────────────────────────────

/// Passkey 認証開始 API（`POST /internal/passkey/login/begin`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPasskeyLoginBeginRequest {
    /// OIDC フローの auth_session_id（Cookie 値）。complete で OIDC フローを継続するために必要。
    pub auth_session_id: Option<String>,
}

/// Passkey 認証開始 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPasskeyLoginBeginResponse {
    /// 開始成功。`challenge_id` を complete で使う。`options` を JS WebAuthn API に渡す。
    Ok {
        challenge_id: String,
        options: serde_json::Value,
    },
    /// api 内部エラー。
    Internal,
}

/// Passkey 認証完了 API（`POST /internal/passkey/login/complete`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPasskeyLoginCompleteRequest {
    /// フローのテナント（ADR-0009 §8）。**必須**。api は未指定・不正な UUID を 400 で拒否する（fail-closed。SEC4）。
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub challenge_id: String,
    /// ブラウザの `navigator.credentials.get()` が返したオブジェクト（JSON）。
    pub credential: serde_json::Value,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Passkey 認証完了 API のレスポンス。成功系は `InternalAuthenticateResponse` と同等。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPasskeyLoginCompleteResponse {
    Success {
        redirect_to: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// チャレンジが見つからない・期限切れ。
    ChallengeNotFound,
    /// AuthSession が無い・期限切れ。
    SessionExpired,
    /// クレデンシャルが無効。
    InvalidCredential,
    /// api 内部エラー。
    Internal,
}

/// セルフサービスの表示言語更新 API（`POST /internal/account/update-language`。MT20）のリクエスト。
///
/// web の設定画面で言語を変更した際、DB の `users.language` を更新する。Cookie の更新は web が行う。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountUpdateLanguageRequest {
    /// SSO セッション Cookie の生値（web が転送）。
    pub sso_session_id: String,
    /// 設定する言語コード（`ja` または `en`）。
    pub language: String,
}

/// セルフサービスの表示言語更新 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountUpdateLanguageResponse {
    Ok,
    /// SSO セッションが無い・期限切れ。
    SessionExpired,
    /// 指定した言語コードが非対応（`ja`・`en` 以外）。
    InvalidLanguage,
    /// api 内部エラー。
    Internal,
}
