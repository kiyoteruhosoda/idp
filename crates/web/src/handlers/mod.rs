//! web のハンドラ。

pub mod admin_authentication_policies_console;
pub mod admin_clients_console;
pub mod admin_console;
pub mod admin_external_idps_console;
pub mod admin_invitations_console;
pub mod admin_login_identifiers_console;
pub mod admin_members_console;
pub mod admin_restart_console;
pub mod admin_saml_clients_console;
pub mod admin_settings;
pub mod admin_signing_keys_console;
pub mod admin_status_console;
pub mod admin_tenants_console;
pub mod admin_users_console;
pub mod authenticators;
pub mod consent;
pub mod console_script;
pub mod external_login;
pub mod health;
pub mod invitation_accept;
pub mod login;
pub mod mfa_totp;
pub mod page_scripts;
pub mod passkey;
pub mod password_change;
pub mod password_reset;
pub mod portal;
pub mod react_assets;
pub mod rp_logout;
pub mod saml_sso;
pub mod step_up;
pub mod stylesheet;
pub mod submit_feedback_script;
pub mod user_security;
pub mod user_settings;
pub mod vendor_assets;
pub mod verify_email;

use crate::api_client::InternalCallError;
use crate::client_ip::ClientIp;
use crate::correlation::CorrelationId;
use crate::i18n::Locale;
use axum::http::header::{HeaderValue, ACCEPT_LANGUAGE, LOCATION, USER_AGENT};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use idp_contracts::auth::PasswordRejectionReason;

/// `/internal/*` 呼び出しの失敗を、画面へ返すステータスコードへ写す（MT28）。
///
/// **テナントを解決できなかった（URL のテナント ID が不存在・`DISABLED`）ときだけ 404。**
/// テナントプレフィクス付きの他の経路（api の `TenantResolver` が返す 404）と揃える —— これは
/// 利用者の入力の誤りであって、web の実装/構成エラーではない。区別が無かった頃は、存在しない
/// テナント ID を打っただけでログイン送信が素の 502 になっていた。
///
/// それ以外は従来どおり 502（api へ到達できない・応答が壊れている・トークン不一致）。
///
/// 本文は共通のエラーページ middleware（[`crate::error_pages`]）が補完するので、ここは
/// ステータスだけを決める。
pub(crate) fn internal_call_status(error: &InternalCallError) -> StatusCode {
    match error {
        InternalCallError::UnknownTenant => StatusCode::NOT_FOUND,
        InternalCallError::Failed(_) => StatusCode::BAD_GATEWAY,
    }
}

/// 表示言語を決める（MT20）。
///
/// 決定順（`?lang=` > ユーザー設定 > Cookie > ブラウザ言語 > 既定 `ja`）のうち上位 2 つは
/// [`crate::language::resolve_language`] middleware が解決し、結果を**リクエストの `lang` Cookie へ
/// 正規化して**渡してくる。したがってここでは Cookie > `Accept-Language` > 既定 `ja` を見れば足りる。
///
/// 優先順位の判断を middleware 1 箇所に集約するため、ハンドラは `?lang=` を自前で解釈しない
/// （画面ごとに解釈すると、画面が増えたときに優先順位が食い違う）。
pub(crate) fn locale(headers: &HeaderMap) -> Locale {
    let cookie_lang = crate::cookies::get(headers, crate::cookies::LANG_COOKIE);
    Locale::resolve(
        None,
        None,
        cookie_lang.as_deref(),
        headers.get(ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()),
    )
}

/// PRG（Post/Redirect/Get）で戻ったフォームページの `?error=` をエラーバナーの翻訳キーへ写す。
/// CSRF 不一致の POST は 303 で `?error=csrf` 付きの GET へ付け替え、新しいトークンのフォームを
/// 自動で再表示する（POST 応答のままエラーページを返すと、リロードが再送信になり復帰できない）。
pub(crate) fn form_retry_error_key(error: Option<&str>) -> Option<&'static str> {
    match error {
        Some("csrf") => Some("login-error-csrf-retry"),
        _ => None,
    }
}

/// パスワードが拒否された理由（AP7）を、画面に出す文言キーへ写す。
///
/// 長さ等（`Policy`）だけ画面ごとに既存のキーがあるため呼び出し側から受け取り、漏えい済み・
/// 再利用は**全画面共通のキー**を使う。理由ごとに違う文言を出すのは、利用者が次に取るべき
/// 行動が違うためである（伸ばす／別の値を考える）。
pub(crate) fn password_rejection_key(
    reason: PasswordRejectionReason,
    policy_key: &'static str,
) -> &'static str {
    match reason {
        PasswordRejectionReason::Policy => policy_key,
        PasswordRejectionReason::Breached => "password-error-breached",
        PasswordRejectionReason::Reused => "password-error-reused",
    }
}

/// 上記を PRG リダイレクトの `?error=` コードへ写す（フォームを再表示せずに戻す画面用）。
pub(crate) fn password_rejection_error_code(
    reason: PasswordRejectionReason,
    policy_code: &'static str,
) -> &'static str {
    match reason {
        PasswordRejectionReason::Policy => policy_code,
        PasswordRejectionReason::Breached => "breached",
        PasswordRejectionReason::Reused => "reused",
    }
}

/// 内部認証呼び出しへ転送する接続元情報。
pub(crate) struct ForwardedContext {
    pub correlation_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// api へ転送する接続元情報を組み立てる。
///
/// IP は**ここでヘッダから読まない**。`X-Forwarded-For` を信じてよいかの判定
/// （`TRUST_FORWARDED_HEADERS`）と接続元アドレスへのフォールバックは
/// [`crate::client_ip::resolve_client_ip`] middleware が一括で行い、結果を `Extension<ClientIp>`
/// で渡してくる（SEC1）。ハンドラごとにヘッダを読むとゲートの掛け忘れが混ざるため。
pub(crate) fn forwarded_context(
    headers: &HeaderMap,
    correlation: &CorrelationId,
    client_ip: &ClientIp,
) -> ForwardedContext {
    let ip_address = client_ip.0.clone();
    let user_agent = headers
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    ForwardedContext {
        correlation_id: correlation.0.clone(),
        ip_address,
        user_agent,
    }
}

/// `302 Found` リダイレクト（設計仕様 §4.2。axum の `Redirect::to` は 303 のため使わない）。
pub(crate) fn found(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(value) => (StatusCode::FOUND, [(LOCATION, value)]).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "redirect location is not a valid header value");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `303 See Other` リダイレクト。ハンドオフ URL の単回ハンドル（`?auth_session=`）をアドレスバー・
/// 履歴から即座に除去する自 URL への付け替えに使う（ADR-0018 決定 2）。
pub(crate) fn see_other(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(value) => (StatusCode::SEE_OTHER, [(LOCATION, value)]).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "redirect location is not a valid header value");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
