//! 内部認証 API（`/internal/authenticate*`、ADR-0007 §3）の DTO 契約。
//!
//! web（ログイン画面）→api の内部認証呼び出しで共有する。web が [`InternalAuthenticateRequest`] /
//! [`InternalAdminAuthenticateRequest`] を送信（serialize）し、api が受信（deserialize）する。応答は
//! `result` タグで判別し、成功時のみ SSO/redirect 情報を含む。Cookie 組み立て（Secure/HttpOnly/
//! SameSite/TTL）とエラー文言のローカライズは呼び出し側（web）が担う。
//!
//! `/internal/*` は外部公開しない内部 I/F のため OpenAPI（`utoipa::ToSchema`）には含めない。

use serde::{Deserialize, Serialize};

/// api が**テナントを解決できなかった**ときに `/internal/*` のエラー本文へ載せるコード（MT28）。
///
/// `/internal/*` はテナントプレフィクスを持たないため §7 の `TenantResolver` middleware を通らず、
/// `tenant_id` は本文のフィールドとして届く。不存在・`DISABLED` のときは 400 で拒否するが、
/// **他の 400（本文の不正等）と機械的に区別できる必要がある** —— web はこれだけを 404 の画面へ
/// 倒し、それ以外は「web の実装/構成エラー」として 502 に倒すためである。説明文（人間向け）で
/// 判別すると、文言を直した瞬間に静かに壊れる。
///
/// 値の一致が api と web で崩れると「不存在テナントが 502 になる」に戻るだけで気付きにくいので、
/// `contracts` に単一定義する。
pub const UNKNOWN_TENANT_ERROR_CODE: &str = "unknown_tenant";

/// 認可フロー再開 API（`POST /internal/authorize/resume`、ADR-0018 決定 2）のリクエスト。
///
/// api の `/authorize` はブラウザ Cookie を読まず、web へのリダイレクト URL に単回・短命の
/// ハンドル（`?auth_session=`）を載せる。web はハンドルと**自ドメインの host-only**
/// `sso_session_id` Cookie の値を本 API へ渡し、api がハンドル交換（単回消費）と SSO 判定・
/// 同意チェック・code 発行までを行う（`/internal/authenticate` と同じ応答パターン）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAuthorizeResumeRequest {
    /// フローのテナント（ADR-0009 §8）。**必須**。api は未指定・不正な UUID を 400 で拒否する（fail-closed。SEC4）。
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// `/authorize` がリダイレクト URL に載せた単回ハンドル。
    pub handle: String,
    /// web の host-only `sso_session_id` Cookie の値（無ければ `None` = 未ログイン）。
    #[serde(default)]
    pub sso_session_id: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 認可フロー再開 API のレスポンス。`result` タグで判別する。
///
/// SSO 復元に成功した応答（`Redirect`・`ConsentRequired`）には `sso_absolute_ttl_secs` を含める。
/// web はこれで手元の `sso_session_id` を host-only で**再発行**する。`COOKIE_DOMAIN`（旧 ADR-0012
/// 構成の掃除）設定中は再発行に旧 `Domain` 付き Cookie の削除が併送されるため、明示的な
/// ログイン・ログアウトを経ない既存セッションもサイレント復元の時点で host-only へ移行し、
/// 旧親ドメイン配下（stg 等）へ bearer credential が送信され続ける露出を閉じる。
/// `response_mode=form_post` の認可応答で POST する hidden フィールド（G12）。
///
/// `None` は `query`（`redirect_to` へ 302 する）。`Some` のとき web は、`redirect_to` を
/// action にした**自動送信フォーム**を描いてこのフィールドを POST する。
///
/// フィールドを URL へ畳んだ形で渡さないのは、`redirect_uri` 自身がクエリを持ち得るため
/// 「どこまでが RP のクエリでどこからが認可応答か」を URL からは復元できないからである。
/// この形のとき `redirect_to` には**認可応答のパラメータが載っていない**（見落とした経路が
/// 302 しても、認可コードが履歴・`Referer` に残らない）。
pub type FormPostFields = Vec<(String, String)>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAuthorizeResumeResponse {
    /// SSO 有効かつ同意済み。code 発行済みの `redirect_to`（RP URL）へ 302 する。
    Redirect {
        redirect_to: String,
        /// `form_post` のとき POST する hidden フィールド（G12）。`None` は `query`。
        #[serde(default)]
        form_post: Option<FormPostFields>,
        sso_absolute_ttl_secs: u64,
    },
    /// リクエスト続行不可（`prompt=none` で未ログイン・未同意など）。エラーコード付きの
    /// `redirect_to`（RP URL）へ 302 する。
    ErrorRedirect { redirect_to: String },
    /// SSO 有効だが同意が必要。web は `auth_session_id` を host-only Cookie 化して `/consent` へ。
    ConsentRequired {
        auth_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// 認証が必要。web は `auth_session_id` を host-only Cookie 化してログインフォームを表示する。
    LoginRequired { auth_session_id: String },
    /// ハンドルが無効・期限切れ・使用済み（`/authorize` からやり直し）。
    ExpiredHandle,
    /// api 内部エラー。
    Internal,
}

/// ログイン画面の文脈取得 API（`POST /internal/authorize/login-context`。G12）のリクエスト。
///
/// `/authorize` が受け取った `login_hint` / `ui_locales` は auth_session に保存されるが、web は
/// resume の 303（ハンドルを URL から外す付け替え）で状態を落とすため、ログイン画面の描画時に
/// 手元へ残っていない。web は host-only `auth_session_id` Cookie の値を渡して取り直す。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAuthorizeLoginContextRequest {
    /// フローのテナント（ADR-0009 §8）。**必須**。api は未指定・不正な UUID を 400 で拒否する。
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// web の host-only `auth_session_id` Cookie の値。
    pub auth_session_id: String,
}

/// ログイン画面の文脈取得 API のレスポンス。`result` タグで判別する。
///
/// 認可要求が持ち込んだ**表示上のヒントだけ**を返す（利用者・資格情報・同意状態は含めない）。
/// `login_hint` は RP が指定した任意の文字列であり、実在するアカウントを意味しない。
/// `client_name` / `tenant_name` は IdP が登録済みの値から引いた表示名で、RP の申告ではない。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAuthorizeLoginContextResponse {
    Ok {
        /// `login_hint`（ログイン欄のプリフィル用。未指定は `None`）。
        login_hint: Option<String>,
        /// `ui_locales`（空白区切りの BCP47 タグ。未指定は `None`）。
        ui_locales: Option<String>,
        /// この認可要求の `redirect_uri`（登録済みの値と完全一致したもの）。
        ///
        /// **web が CSP の `form-action` に許可するオリジンの出所である。** ログインフォームの
        /// 送信は、SSO と同意が揃っていればそのまま RP へリダイレクトする。Chrome は
        /// `form-action` をフォーム送信後のリダイレクト先にも適用するため、RP のオリジンを
        /// 許可しないとその遷移が遮断される（SAML の ACS と同じ事情。`handlers::saml_sso`）。
        redirect_uri: Option<String>,
        /// 認可要求を出したクライアントの表示名。ログイン画面の見出し
        /// （「〇〇 にログイン」）に使う。
        ///
        /// **`Option` かつ `#[serde(default)]` なのは配信順への耐性のためである**
        /// （`InternalConsentInfoResponse::Ok` の `redirect_uri` と同じ事情。api と web の
        /// 入れ替えの数秒間は「新しい web ＋ 古い api」が成立し得る）。`None` のときは
        /// 表示名を出さない（＝この画面が変わる前の見出しに戻るだけ）。
        #[serde(default)]
        client_name: Option<String>,
        /// フローのテナントの表示名。ログイン画面のナビバーに出す。`None` のときは既定の
        /// `IdP` を出す（`client_name` と同じく配信順への耐性のため `Option`）。
        #[serde(default)]
        tenant_name: Option<String>,
    },
    /// `auth_session_id` が無効・期限切れ（web は文脈なしで描画を続ける）。
    SessionExpired,
    /// api 内部エラー。
    Internal,
}

/// SAML SSO 再開 API（`POST /internal/saml/resume`）のリクエスト。
///
/// api の `/{tenant_id}/saml/sso` は AuthnRequest を検証して web の `/saml/continue` へ
/// 単回・短命のハンドル付きで 302 する（OIDC の `/authorize` と同じハンドオフ。ADR-0018 決定 2）。
/// web は初回はハンドル、ログイン後の再開は `saml_request_id`（host-only Cookie）を、自ドメインの
/// `sso_session_id` Cookie の値とともに本 API へ渡す。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalSamlResumeRequest {
    /// フローのテナント（ADR-0009 §8）。**必須**。api は未指定・不正な UUID を 400 で拒否する。
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// `/saml/sso` がリダイレクト URL に載せた単回ハンドル（初回のみ）。
    #[serde(default)]
    pub handle: Option<String>,
    /// ログイン後の再開に使う進行状態 id（web の host-only `saml_request_id` Cookie の値）。
    #[serde(default)]
    pub saml_request_id: Option<String>,
    /// web の host-only `sso_session_id` Cookie の値（無ければ `None` = 未ログイン）。
    #[serde(default)]
    pub sso_session_id: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// SAML SSO 再開 API のレスポンス。`result` タグで判別する。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalSamlResumeResponse {
    /// SSO 有効。web は `acs_url` へ `SAMLResponse`（base64 済み）と `relay_state` を自動 POST する
    /// フォームを描画し、`saml_request_id` Cookie を失効させる。
    Completed {
        acs_url: String,
        saml_response: String,
        #[serde(default)]
        relay_state: Option<String>,
    },
    /// 認証が必要。web は `saml_request_id` を host-only Cookie 化してポータルログインへ誘導する。
    LoginRequired { saml_request_id: String },
    /// ハンドル・進行状態が無効・期限切れ・使用済み（SP からやり直し）。
    Expired,
    /// api 内部エラー。
    Internal,
}

/// RP-initiated Logout の内部 API（`POST /internal/logout/rp`、ADR-0018 決定 2）のリクエスト。
///
/// OIDC の `end_session_endpoint` は web（`GET /{tenant_id}/logout`）が受け、web が自ドメインの
/// `sso_session_id` Cookie とクエリパラメータを本 API へ転送する。api は SSO セッションの失効・
/// back-channel 通知・`post_logout_redirect_uri` の検証と組み立て（`state` 付与を含む）を担い、
/// **SSO Cookie の破棄と front-channel iframe ページの描画は web が行う**。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalRpLogoutRequest {
    /// ログアウト対象フローのテナント（ADR-0009 §8）。**必須**。api は未指定・不正な UUID を 400 で拒否する。
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// web の host-only `sso_session_id` Cookie の値（無ければ `None` = ログアウト済み扱い）。
    #[serde(default)]
    pub sso_session_id: Option<String>,
    /// `client_id` クエリ（`post_logout_redirect_uri` の検証に使う。任意）。
    #[serde(default)]
    pub client_id: Option<String>,
    /// `id_token_hint` クエリ（OIDC RP-Initiated Logout 1.0 §2。G12）。api が署名・issuer を
    /// 検証し、`aud` を `post_logout_redirect_uri` の照合先に、`sub` を「誰のログアウトか」の
    /// 確認に使う。期限切れでも受け付ける（hint は過去に発行した ID Token であるため）。
    #[serde(default)]
    pub id_token_hint: Option<String>,
    /// RP が指定したログアウト後のリダイレクト先（登録済みのもののみ許可される）。
    #[serde(default)]
    pub post_logout_redirect_uri: Option<String>,
    /// RP が受け取るランダム値（検証済み redirect URI に透過的に付与される）。
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// RP-initiated Logout の内部 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalRpLogoutResponse {
    /// ログアウト処理完了（セッションが無かった場合も冪等に成功）。web は SSO Cookie を破棄し、
    /// `frontchannel_uris` があれば iframe ページを描画、無ければ `redirect_to` へ 302
    /// （どちらも無ければ完了ページを表示）する。
    Ok {
        /// front-channel logout の iframe に読み込ませる URI 群（`iss` クエリ付与済み）。
        frontchannel_uris: Vec<String>,
        /// 検証済みの post-logout リダイレクト先（`state` 付与済み。未指定・検証失敗は `None`）。
        redirect_to: Option<String>,
    },
    /// `id_token_hint` が指す利用者と、web が転送したセッションの利用者が一致しないため
    /// **何もしなかった**（G12）。web は **SSO Cookie を消してはならない** —— 消すと DB には
    /// セッションが生きたままブラウザから戻れなくなり、守ろうとした別利用者のログイン状態を
    /// 結局は壊してしまう。画面は「何も変更していない」ことを伝える。
    SubjectMismatch,
    /// api 内部エラー。
    Internal,
}

/// 内部認証 API（`POST /internal/authenticate`）のリクエスト。
///
/// web が資格情報・`auth_session_id` 参照・接続元情報（`X-Forwarded-For` 由来 IP・User-Agent）を
/// api へ転送する。CSRF は `csrf_token`（`auth_session_id` 由来）を api の LoginService が検証する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAuthenticateRequest {
    /// フローのテナント（ADR-0009 §8）。認証の対象は当該テナントの ACTIVE なメンバー（所属元の
    /// HOME と、招待で参加している GUEST）に限られるため、テナント指定のない認証は成立しない。
    /// **必須**。api は未指定・不正な UUID を 400 で拒否する（fail-closed。SEC4）。
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub auth_session_id: Option<String>,
    /// ログイン識別子（ユーザー名 = `preferred_username`。ADR-0009 §8）。既定では email と同値
    /// （作成時に未指定なら email を採用）だが、照合は `preferred_username` に対して行う。
    pub username: String,
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
        /// `form_post` のとき POST する hidden フィールド（G12）。`None` は `query`。
        #[serde(default)]
        form_post: Option<FormPostFields>,
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
    /// 認証ポリシーにより拒否（ユーザー認証・認証ポリシー仕様書 §7.4 `deny`）。
    /// web は「組織のポリシーで拒否された」旨を表示する（資格情報は検証済みのため列挙リスクは無い）。
    PolicyDenied,
    /// 認証ポリシーが MFA を必須としたが、使用可能な認証器（確認済み TOTP）が無い。
    /// web はポータルから MFA を設定するよう案内する。
    MfaEnrollmentRequired,
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
        /// `form_post` のとき POST する hidden フィールド（G12）。`None` は `query`。
        #[serde(default)]
        form_post: Option<FormPostFields>,
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
    /// IP 単位のレート制限に掛かった（SEC3）。
    RateLimited,
    /// アカウントがロック中（TOTP の連続失敗、またはパスワード認証側の失敗によるロック。SEC3）。
    Locked,
    /// 認証ポリシーにより拒否された（AP2/AP3）。第二要素まで通っていても、`deny` へ変わった場合や
    /// `require_specific_method` を満たさない方式だった場合はここへ来る。
    PolicyDenied,
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

/// 新しいパスワードが受け付けられなかった理由（AP7）。
///
/// 「弱い」の一語にまとめないのは、利用者が次に取るべき行動が理由ごとに違うためである
/// （長さ不足は伸ばせばよいが、漏えい・再利用は**別の値を考える**しかない）。web はこの値を
/// 画面の文言キーへ写す。
///
/// 既定は `Policy`（長さ等）。理由を持たない古い応答を読んでも従来と同じ表示になる。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordRejectionReason {
    /// 長さ等、入力そのものの要件を満たさない。
    #[default]
    Policy,
    /// 既知の漏えいパスワード。
    Breached,
    /// 現行または過去に使ったパスワードの再利用。
    Reused,
}

/// パスワード変更 API のレスポンス。成功系は `InternalAuthenticateResponse` と同等。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalChangePasswordResponse {
    Success {
        redirect_to: String,
        /// `form_post` のとき POST する hidden フィールド（G12）。`None` は `query`。
        #[serde(default)]
        form_post: Option<FormPostFields>,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// 変更成功だが認証ポリシーが MFA を必須とし、TOTP 設定済み。`auth_session_id` Cookie を維持して
    /// TOTP 入力画面 `/mfa/totp` へ誘導する（SSO はまだ発行しない）。
    MfaRequired {
        auth_session_id: String,
    },
    /// 変更は成功したが認証ポリシーによりログインを拒否（仕様 §7.4 `deny`）。
    PolicyDenied,
    /// 変更は成功したが認証ポリシーが MFA を必須とし、使用可能な認証器（確認済み TOTP）が無い。
    /// web はポータルから MFA を設定するよう案内する。
    MfaEnrollmentRequired,
    SessionExpired,
    CsrfMismatch,
    /// 現行パスワードが不一致。
    InvalidCurrentPassword,
    /// 新パスワードがポリシーを満たさない（長さ・漏えい済み・再利用）。
    WeakPassword {
        #[serde(default)]
        reason: PasswordRejectionReason,
    },
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
    /// 新パスワードがポリシーを満たさない（長さ・漏えい済み・再利用）。
    WeakPassword {
        #[serde(default)]
        reason: PasswordRejectionReason,
    },
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
    /// 新パスワードがポリシーを満たさない（長さ・漏えい済み・再利用）。
    WeakPassword {
        #[serde(default)]
        reason: PasswordRejectionReason,
    },
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
    /// ログイン識別子（ユーザー名 = `preferred_username`。ADR-0009 §8）。
    pub username: String,
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
    /// `username` はフォーム再表示用に入力値をそのまま返す。SSO はまだ発行しない。
    PasswordChangeRequired { username: String },
    /// 認証ポリシーにより拒否（AP2。ユーザー認証・認証ポリシー仕様書 §7.4 `deny`）。
    PolicyDenied,
    /// 認証ポリシーが MFA を必須としたが、使用可能な認証器（確認済み TOTP）が無い（AP2）。
    MfaEnrollmentRequired,
    /// 認証ポリシーが MFA を必須で、認証器は登録済み（AP2）。管理コンソールのログインは第二要素の
    /// 入力ステップを持たないため、ポータルログインで MFA を通してから入るよう案内する。
    MfaRequired,
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
    /// ログイン識別子（ユーザー名 = `preferred_username`。ADR-0009 §8）。
    pub username: String,
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
    /// 新パスワードがポリシーを満たさない（長さ・漏えい済み・再利用）。
    WeakPassword {
        #[serde(default)]
        reason: PasswordRejectionReason,
    },
    /// 変更は成功したが認証ポリシーにより拒否（AP2）。
    PolicyDenied,
    /// 変更は成功したが認証ポリシーが MFA を必須とし、使用可能な認証器が無い（AP2）。
    MfaEnrollmentRequired,
    /// 変更は成功したが認証ポリシーが MFA を必須（認証器は登録済み。AP2）。
    MfaRequired,
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
    /// ログイン識別子（ユーザー名 = `preferred_username`。ADR-0009 §8）。
    pub username: String,
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
    /// （管理コンソールと同方式。`username` は入力値をフォーム再表示用にそのまま返す）。
    PasswordChangeRequired { username: String },
    /// 認証ポリシーにより拒否（AP2。仕様 §7.4 `deny`）。
    PolicyDenied,
    /// 認証ポリシーが MFA を必須としたが、使用可能な認証器（確認済み TOTP）が無い（AP2）。
    MfaEnrollmentRequired,
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
    /// ログイン識別子（ユーザー名 = `preferred_username`）。
    pub username: String,
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
    /// 変更は成功したが認証ポリシーにより拒否（AP2）。
    PolicyDenied,
    /// 変更は成功したが認証ポリシーが MFA を必須とし、使用可能な認証器が無い（AP2）。
    MfaEnrollmentRequired,
    RateLimited,
    /// 資格情報不正（利用者不存在・現行パスワード不一致・無効アカウント等を区別しない）。
    InvalidCredentials,
    Locked,
    /// 新パスワードがポリシーを満たさない（長さ・漏えい済み・再利用）。
    WeakPassword {
        #[serde(default)]
        reason: PasswordRejectionReason,
    },
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
    /// 認証ポリシーにより拒否（AP2。チケット発行後にポリシーが変わった場合）。
    PolicyDenied,
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
        /// この認可要求の `redirect_uri`（登録済みの値と完全一致したもの）。
        ///
        /// **web が CSP の `form-action` に許可するオリジンの出所である。** 同意フォームの送信は
        /// RP へのリダイレクトで終わり、Chrome は `form-action` をフォーム送信後のリダイレクト先にも
        /// 適用する。許可しないと、同意は記録されコードも発行されたのにブラウザが RP へ戻れない。
        ///
        /// **`Option` なのは配信順への耐性のためである。** api と web は別コンテナで、入れ替えの
        /// 数秒間は「新しい web ＋ 古い api」が成立し得る。必須にすると、その窓で本応答の
        /// デシリアライズが失敗し**同意画面ごと落ちる**。`None` のときは許可を足さない（＝この不具合が
        /// 直る前の状態に戻るだけ）に留める。姉妹の `InternalAuthorizeLoginContextResponse::Ok` も同じ。
        #[serde(default)]
        redirect_uri: Option<String>,
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
    Success {
        redirect_to: String,
        /// `form_post` のとき POST する hidden フィールド（G12）。`None` は `query`。
        #[serde(default)]
        form_post: Option<FormPostFields>,
    },
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
    Ok {
        redirect_to: String,
        /// `form_post` のとき POST する hidden フィールド（G12）。`None` は `query`。
        /// エラーも成功と同じ `response_mode` で返す（RP は同じ受け口で待っている）。
        #[serde(default)]
        form_post: Option<FormPostFields>,
    },
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
    ///
    /// **`None` は認可フロー外の直接ログイン**（管理コンソール・ポータル）用のチャレンジになる。
    /// チャレンジの用途はこの有無で決まり、完了 API は自分の用途と違うチャレンジを受け付けない。
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
        /// `form_post` のとき POST する hidden フィールド（G12）。`None` は `query`。
        #[serde(default)]
        form_post: Option<FormPostFields>,
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
    /// 認証ポリシーにより拒否（ユーザー認証・認証ポリシー仕様書 §7.4 `deny`）。
    PolicyDenied,
    /// api 内部エラー。
    Internal,
}

/// 管理コンソールの Passkey ログイン完了 API（`POST /internal/passkey/login/admin/complete`）の
/// リクエスト。開始は 3 経路共通の `POST /internal/passkey/login/begin` を `auth_session_id`
/// なしで呼ぶ（＝直接ログイン用のチャレンジ）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAdminPasskeyLoginCompleteRequest {
    /// ログイン先テナント（ADR-0009 §8）。**必須**。api は未指定・不正な UUID を 400 で拒否する。
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

/// 管理コンソールの Passkey ログイン完了 API のレスポンス。
///
/// パスワード経路（`InternalAdminAuthenticateResponse`）に在る `Locked` /
/// `PasswordChangeRequired` / `MfaRequired` / `MfaEnrollmentRequired` はここには無い。パスキーは
/// パスワードを使わず、単独で `require_mfa` を満たすためである。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAdminPasskeyLoginCompleteResponse {
    /// 認証成功かつ テナント admin 権限を保有。`sso_session_id` を Cookie 化して管理コンソールへ。
    Success {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// チャレンジが見つからない・期限切れ・用途違い。やり直しを促す。
    ChallengeNotFound,
    /// クレデンシャルが無効（不存在・検証失敗・停止中・テナント非所属・アカウント無効）。
    InvalidCredential,
    /// パスキーは正しいが テナント admin 権限を保有しない。
    Forbidden,
    /// 認証ポリシーにより拒否（AP2。仕様 §7.4 `deny`）。
    PolicyDenied,
    /// IP 単位のレート制限超過。
    RateLimited,
    /// api 内部エラー。
    Internal,
}

/// ポータルの Passkey ログイン完了 API（`POST /internal/passkey/login/portal/complete`）の
/// リクエスト。開始は 3 経路共通の `POST /internal/passkey/login/begin` を `auth_session_id`
/// なしで呼ぶ（＝直接ログイン用のチャレンジ）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPortalPasskeyLoginCompleteRequest {
    /// ログイン先テナント（ADR-0009 §8）。**必須**。api は未指定・不正な UUID を 400 で拒否する。
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

/// ポータルの Passkey ログイン完了 API のレスポンス。
///
/// パスワード経路（`InternalPortalAuthenticateResponse`）に在る `MfaRequired` /
/// `MfaEnrollmentRequired` / `Locked` / `PasswordChangeRequired` はここには無い（パスキーは
/// 単独で `require_mfa` を満たし、パスワードを使わない）。メール未検証のゲートは残る。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPortalPasskeyLoginCompleteResponse {
    /// 認証成功。`sso_session_id` を Cookie 化してアカウント画面へ。
    Success {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
        #[serde(default)]
        user_language: Option<String>,
    },
    /// チャレンジが見つからない・期限切れ・用途違い。やり直しを促す。
    ChallengeNotFound,
    /// クレデンシャルが無効（不存在・検証失敗・停止中・テナント非所属・アカウント無効）。
    InvalidCredential,
    /// 自己登録アカウントのメール未検証（SEC6b）。確認リンクを踏むよう案内する。
    EmailVerificationRequired,
    /// 認証ポリシーにより拒否（AP2。仕様 §7.4 `deny`）。
    PolicyDenied,
    /// IP 単位のレート制限超過。
    RateLimited,
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

/// セルフサービスの配色更新 API（`POST /internal/account/update-theme`）のリクエスト。
///
/// ログイン済みユーザーが SSO セッション経由で自分の `users.theme` を更新する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountUpdateThemeRequest {
    /// SSO セッション Cookie の生値（web が転送）。
    pub sso_session_id: String,
    /// 設定する配色（`light` / `dark` / `system`）。
    pub theme: String,
}

/// セルフサービスの配色更新 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountUpdateThemeResponse {
    Ok,
    /// SSO セッションが無い・期限切れ。
    SessionExpired,
    /// 指定した配色が非対応。
    InvalidTheme,
    /// api 内部エラー。
    Internal,
}

/// セルフサービスのプロフィール取得 API（`POST /internal/account/profile`）のリクエスト。
///
/// 設定画面が現在の表示名などを再表示（プリフィル）するために、SSO セッション経由で本人の
/// プロフィールを取得する。取得のみで副作用は無い（POST なのは SSO を body で転送するため）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountProfileRequest {
    /// SSO セッション Cookie の生値（web が転送）。
    pub sso_session_id: String,
}

/// セルフサービスのプロフィール取得 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountProfileResponse {
    Ok {
        /// 表示名（未設定なら `None`）。
        name: Option<String>,
        /// ログイン識別子（未設定なら `None`）。表示のみ・変更不可。
        preferred_username: Option<String>,
        /// メールアドレス。
        email: String,
        /// 保存済みの表示言語（`ja` / `en`。未設定なら `None`）。web の表示言語決定で
        /// Cookie より優先する（MT20。`CLAUDE.md`「国際化」の優先順 2 位）。
        #[serde(default)]
        language: Option<String>,
        /// 保存済みの配色（`light` / `dark` / `system`。未設定なら `None`）。言語と同じく
        /// Cookie より優先する。旧 api と混在しても復号に失敗しないよう `#[serde(default)]`。
        #[serde(default)]
        theme: Option<String>,
    },
    /// SSO セッションが無い・期限切れ。
    SessionExpired,
    /// api 内部エラー。
    Internal,
}

/// セルフサービスの表示名更新 API（`POST /internal/account/update-name`）のリクエスト。
///
/// ログイン済みユーザーが SSO セッション経由で自分の `users.name`（表示名）を更新する。
/// `name` が空文字・空白のみ・`None` の場合は表示名を解除（DB は `NULL`）する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountUpdateNameRequest {
    /// SSO セッション Cookie の生値（web が転送）。
    pub sso_session_id: String,
    /// 新しい表示名。空・空白のみ・未指定は解除扱い。
    #[serde(default)]
    pub name: Option<String>,
}

/// セルフサービスの表示名更新 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountUpdateNameResponse {
    Ok,
    /// SSO セッションが無い・期限切れ。
    SessionExpired,
    /// 表示名が長すぎる等、値が不正。
    Invalid,
    /// api 内部エラー。
    Internal,
}

/// 切り替え可能なテナント 1 件の要約（テナント切り替え UI 用）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountTenantSummary {
    /// テナントの内部 ID（URL プレフィクスに使う）。
    pub tenant_id: String,
    /// テナント表示名。
    pub name: String,
    /// メンバーシップ種別（`HOME` / `GUEST`）。
    pub membership_type: String,
}

/// セルフサービスの所属テナント一覧 API（`POST /internal/account/tenants`）のリクエスト。
///
/// ログイン中ユーザーが `ACTIVE` なメンバーシップを持つテナントを列挙する（テナント切り替え用）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountTenantsRequest {
    /// SSO セッション Cookie の生値（web が転送）。
    pub sso_session_id: String,
}

/// セルフサービスの所属テナント一覧 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountTenantsResponse {
    Ok {
        tenants: Vec<AccountTenantSummary>,
    },
    /// SSO セッションが無い・期限切れ。
    SessionExpired,
    /// api 内部エラー。
    Internal,
}

// ── セルフサービスのセキュリティ画面（G10） ──────────────────────────────────

/// ログイン中セッション 1 件の要約（セキュリティ画面）。
///
/// `id` は失効要求で指すための表示用 ID。SSO Cookie の値でも DB の主キー（`session_hash`）でも
/// なく、そこから非可逆に導いた値なので、提示しても他人のセッションを解決・詐称する材料にならない。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSessionSummary {
    pub id: String,
    /// 今このブラウザで使っているセッションか（画面で「現在のセッション」と示す）。
    pub current: bool,
    /// 認証時刻（RFC 3339）。
    pub auth_time: String,
    /// 第二要素まで完了しているか（AP4 の記録）。
    pub multi_factor: bool,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    pub created_at: String,
    /// 無操作での失効時刻（RFC 3339）。
    pub idle_expires_at: String,
    /// 絶対期限（RFC 3339）。
    pub absolute_expires_at: String,
}

/// 連携済みアプリ 1 件の要約（セキュリティ画面）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountConnectedAppSummary {
    pub client_id: String,
    /// 表示名（クライアントが削除済みなら `client_id` と同じ値になる）。
    pub app_name: String,
    pub scopes: Vec<String>,
    pub granted_at: String,
    pub updated_at: String,
}

/// セキュリティ画面の表示内容取得 API（`POST /internal/account/security`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountSecurityRequest {
    /// フローのテナント（連携済みアプリはテナント単位で持つため必須）。
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// SSO セッション Cookie の生値（web が転送）。
    pub sso_session_id: String,
}

/// セキュリティ画面の表示内容取得 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountSecurityResponse {
    Ok {
        sessions: Vec<AccountSessionSummary>,
        connected_apps: Vec<AccountConnectedAppSummary>,
    },
    /// SSO セッションが無い・期限切れ・利用者が無効。
    SessionExpired,
    Internal,
}

/// セッション失効 API（`POST /internal/account/security/revoke-session`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountRevokeSessionRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    /// [`AccountSessionSummary::id`] で示した表示用 ID。
    pub session_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// セッション失効 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountRevokeSessionResponse {
    /// 失効した（既に消えていた場合も含む）。
    Ok,
    /// 指定 ID が当人のセッションに無い（他人のセッション・古い画面からの再送）。
    NotFound,
    /// 今使っているセッション自身は切らせない（ログアウト導線へ回す）。
    CurrentSession,
    SessionExpired,
    Internal,
}

/// 連携解除 API（`POST /internal/account/security/revoke-consent`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAccountRevokeConsentRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    pub client_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 連携解除 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAccountRevokeConsentResponse {
    /// 取り消した（同意が無かった場合も含む）。
    Ok,
    SessionExpired,
    Internal,
}

// ── Step-up 認証（AP5） ──────────────────────────────────────────────────────

/// Step-up の判定・検証 API が扱う重要操作。値は `domain::step_up::SensitiveOperation` の
/// 文字列表現と一致させる（api 側で `parse` する）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalStepUpCheckRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// SSO セッション Cookie の生値（web が転送）。
    pub sso_session_id: String,
    /// 対象操作（`change_password` / `manage_authenticators` / `manage_external_identities` /
    /// `revoke_session`）。
    pub operation: String,
}

/// Step-up 判定 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalStepUpCheckResponse {
    /// 直近の本人確認が要件を満たしている。そのまま操作してよい。
    Satisfied,
    /// 本人確認をやり直す必要がある。`second_factor_required` が真なら TOTP まで求める。
    ChallengeRequired {
        second_factor_required: bool,
    },
    /// SSO セッションが無い・期限切れ・利用者が無効。
    SessionExpired,
    /// 未知の操作名（api が受け付けない値）。
    UnknownOperation,
    Internal,
}

/// Step-up 検証 API のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalStepUpVerifyRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    pub operation: String,
    pub password: String,
    /// 第二要素が求められている場合のみ必要。
    #[serde(default)]
    pub totp_code: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Step-up 検証 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalStepUpVerifyResponse {
    /// 確認できた。続けて操作してよい。
    Ok,
    /// パスワードまたは TOTP が不一致（どちらが違うかは返さない）。
    InvalidCredentials,
    /// 第二要素が要るのにコードが提示されていない。
    SecondFactorRequired,
    RateLimited,
    SessionExpired,
    UnknownOperation,
    Internal,
}

// ── 認証器の統合管理（AP9） ──────────────────────────────────────────────────

/// 登録済み認証器 1 件の要約（セキュリティ画面）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSummaryResponse {
    pub id: String,
    /// 種別（`totp` / `webauthn` / `email_otp`）。リカバリーコードは本数で別に返す。
    pub authenticator_type: String,
    /// 状態（`pending` / `active` / `suspended`）。失効済みは返さない。
    pub status: String,
    pub label: String,
    pub created_at: String,
    #[serde(default)]
    pub last_used_at: Option<String>,
}

/// 認証器一覧 API（`POST /internal/account/authenticators`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAuthenticatorsRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
}

/// 認証器一覧 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAuthenticatorsResponse {
    Ok {
        authenticators: Vec<AuthenticatorSummaryResponse>,
        /// 未使用のリカバリーコードの残数。
        recovery_codes_remaining: usize,
        /// 確認済みの電話番号が登録されているか（AP13）。番号そのものは返さない
        /// （PII を web へ持ち出さない。画面は「登録済み」か「登録する」かだけを出し分ける）。
        #[serde(default)]
        phone_registered: bool,
        /// SMS ゲートウェイが設定されているか（AP13）。未設定なら登録導線を出さない
        /// （登録できても送れない画面を並べない）。
        #[serde(default)]
        sms_available: bool,
    },
    SessionExpired,
    Internal,
}

/// 認証器の状態変更 API（`POST /internal/account/authenticators/status`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAuthenticatorStatusRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    pub authenticator_id: String,
    /// 遷移先（`active` / `suspended` / `revoked`）。
    pub status: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 認証器の状態変更 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAuthenticatorStatusResponse {
    Ok,
    /// 指定 ID が当人の認証器に無い。
    NotFound,
    /// その状態へは遷移できない（失効済みを戻す等）。
    InvalidTransition,
    /// 未知の状態名。
    UnknownStatus,
    SessionExpired,
    Internal,
}

/// リカバリーコード発行 API（`POST /internal/account/recovery-codes`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalRecoveryCodesRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// リカバリーコード発行 API のレスポンス。**平文はこの応答でのみ返る**（DB はハッシュのみ）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalRecoveryCodesResponse {
    Ok { codes: Vec<String> },
    SessionExpired,
    Internal,
}

/// email OTP 送信 API（`POST /internal/account/email-otp`）のリクエスト。
///
/// ログイン中の第二要素として使うため、`sso_session_id` ではなく **MFA 待ちの利用者**を指す
/// 必要がある。web はログインフローの `auth_session_id`（OIDC）または `mfa_ticket`（ポータル）を
/// 持っているので、api 側でそこから利用者を解決する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalEmailOtpRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// OIDC ログインフローの `auth_session_id`（MFA 待ち状態）。
    #[serde(default)]
    pub auth_session_id: Option<String>,
    /// ポータルログインの `mfa_ticket`。
    #[serde(default)]
    pub mfa_ticket: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// email OTP 送信 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalEmailOtpResponse {
    /// 送信した（送信先アドレスは返さない）。
    Sent,
    /// SMTP が未設定でメールを送れない。
    Unavailable,
    /// MFA 待ちの状態ではない（セッション・チケットが無効）。
    SessionExpired,
    Internal,
}

// ── SMS OTP と電話番号の登録（AP13） ─────────────────────────────────────────

/// MFA 待ちの利用者へ SMS OTP を送る要求。解決経路は email OTP と同じ。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalSmsOtpRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// OIDC ログインフローの `auth_session_id`（MFA 待ち状態）。
    #[serde(default)]
    pub auth_session_id: Option<String>,
    /// ポータルログインの `mfa_ticket`。
    #[serde(default)]
    pub mfa_ticket: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// SMS OTP 送信 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalSmsOtpResponse {
    /// 送信した（送信先の電話番号は返さない —— PII を web へ持ち出さない）。
    Sent,
    /// SMS ゲートウェイが未設定で送れない。
    Unavailable,
    /// 送信先の電話番号が未登録・未確認。
    NotRegistered,
    /// MFA 待ちの状態ではない（セッション・チケットが無効）。
    SessionExpired,
    Internal,
}

/// 電話番号の登録開始（確認コードの送信）。ログイン済み利用者のセルフサービス操作のため、
/// 対象は `sso_session_id` から解決する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPhoneRegistrationRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    /// 入力どおりの電話番号（正規化は api 側が行う）。
    pub phone_number: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 電話番号の登録開始のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPhoneRegistrationResponse {
    /// 確認コードを送った。
    Sent,
    /// 電話番号として読めない。
    InvalidPhoneNumber,
    /// SMS ゲートウェイが未設定で送れない。
    Unavailable,
    Unauthenticated,
    Internal,
}

/// 電話番号の登録確認（送られたコードの提示）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPhoneConfirmationRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub sso_session_id: String,
    pub code: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 電話番号の登録確認のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalPhoneConfirmationResponse {
    /// 確認できた（以後 SMS OTP が使える）。
    Confirmed,
    /// コードが合わない・期限切れ・確認待ちの登録が無い。
    InvalidCode,
    Unauthenticated,
    Internal,
}

// ── 外部 IdP ログイン（AP10） ────────────────────────────────────────────────

/// ログイン画面に並べる外部 IdP 1 件（有効なもののみ）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalIdpButton {
    /// URL に載せる識別コード。
    pub provider_code: String,
    pub display_name: String,
}

/// 有効な外部 IdP の一覧 API（`POST /internal/external/providers`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalExternalProvidersRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// 有効な外部 IdP の一覧 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalExternalProvidersResponse {
    Ok { providers: Vec<ExternalIdpButton> },
    Internal,
}

/// 外部 IdP ログインの開始 API（`POST /internal/external/start`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalExternalStartRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub provider_code: String,
    /// OIDC 認可フローの途中から呼ぶ場合の `auth_session_id`（ポータル経由なら `None`）。
    #[serde(default)]
    pub auth_session_id: Option<String>,
}

/// 外部 IdP ログインの開始 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalExternalStartResponse {
    /// 外部 IdP の認可エンドポイントへ 302 する。
    Redirect {
        location: String,
    },
    /// プロバイダが無い・無効。
    ProviderUnavailable,
    Internal,
}

/// 外部 IdP からのコールバック API（`POST /internal/external/callback`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalExternalCallbackRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub state: String,
    pub code: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 外部 SAML IdP のアサーションを受け取る API のリクエスト（AP12。ADR-0027）。
///
/// ブラウザが HTTP-POST binding で web の ACS へ運んできた値をそのまま api へ渡す。
/// **どちらも未検証**である（署名を確かめるのは api 側）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalExternalSamlAcsRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// `SAMLResponse`（base64(XML)）。
    pub saml_response: String,
    /// `RelayState`（開始時に発行した値。進行状態を引く鍵）。
    pub relay_state: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 外部 IdP からのコールバック API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalExternalCallbackResponse {
    /// 認証成功。`sso_session_id` を Cookie 化して `redirect_to` へ送る。
    ///
    /// `redirect_to` は OIDC 認可フローの途中から来ていれば code 付きの `redirect_uri`
    /// （RP へ戻る絶対 URL）、そうでなければ `None`（web が自分のアカウント画面へ戻す）。
    /// 認可要求のパラメータは api 側の auth_session にしか無いため、web には組み立てさせない。
    Success {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
        #[serde(default)]
        redirect_to: Option<String>,
        /// `form_post` のとき POST する hidden フィールド（G12）。`None` は `query`。
        #[serde(default)]
        form_post: Option<FormPostFields>,
        #[serde(default)]
        user_language: Option<String>,
    },
    /// 認証は通ったが RP への同意がまだ。web は同意画面へ誘導する。
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
        #[serde(default)]
        user_language: Option<String>,
    },
    /// `state` が無効・期限切れ・二重使用。
    StateExpired,
    /// 外部 IdP での認証は通ったが、対応する利用者が居ない。
    NotLinked,
    /// 対応する利用者は居るが無効・ロック中。
    UserUnavailable,
    /// 認証ポリシーによる拒否。
    PolicyDenied,
    /// 外部 IdP との通信・トークン検証に失敗した。
    ExternalFailure,
    Internal,
}
