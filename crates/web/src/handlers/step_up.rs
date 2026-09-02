//! Step-up 認証の本人確認画面（web。`/{tenant_id}/settings/verify`。AP5）。
//!
//! 重要操作（認証器の追加削除・セッション失効など）の入口で [`require_step_up`] を呼び、足りなければ
//! この画面へ誘導する。確認が通ったら元の画面（`next`）へ戻す。
//!
//! 判定と検証は api（`/internal/step-up/*`）が行い、web は画面と `next` の安全性だけを担う。
//!
//! 確認の手段は 2 つある。**パスワード**（要件が多要素なら TOTP も）と**パスキー**（T38）で、
//! 後者はパスキーで入った利用者のための経路である —— 認証器の管理は step-up の対象なので、
//! パスワードしか受け付けないと「パスキーで入ったのにパスキーを足せない」になる。
//! パスキー経路はブラウザの WebAuthn API を通るため JSON の 2 段構え（begin / complete）で、
//! ログイン画面と同じ `assets/passkey-login.js` を共有する（完了先だけが違う）。
//!
//! # `next` の扱い
//!
//! `next` はブラウザから任意の値が渡る。同一オリジン内の**このテナントのパス**に限って受け付ける
//! （オープンリダイレクトを作らないため）。`//evil.example.com` のような「スキームなし絶対 URL」は
//! ブラウザが別オリジンとして解決するので、単に先頭が `/` かどうかでは足りない。

use super::internal_call_status;
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::handlers::{forwarded_context, found, locale, see_other};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, StepUpChallenge};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalStepUpCheckRequest, InternalStepUpCheckResponse, InternalStepUpPasskeyBeginRequest,
    InternalStepUpPasskeyBeginResponse, InternalStepUpPasskeyVerifyRequest,
    InternalStepUpPasskeyVerifyResponse, InternalStepUpVerifyRequest, InternalStepUpVerifyResponse,
};
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;
use serde_json::json;

/// 重要操作の識別子（api の `domain::step_up::SensitiveOperation` の文字列表現と一致させる）。
/// web 側の呼び出しはこの定数を使い、リテラルを散らさない（綴りがずれると api が
/// `UnknownOperation` を返し、画面が 500 になる）。
pub const MANAGE_AUTHENTICATORS: &str = "manage_authenticators";
pub const REVOKE_SESSION: &str = "revoke_session";

#[derive(Debug, Deserialize)]
pub struct StepUpQuery {
    /// 確認後に戻る先（このテナント配下のパスのみ）。
    #[serde(default)]
    pub next: Option<String>,
    /// 対象操作（api の `SensitiveOperation` と同じ文字列）。
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StepUpForm {
    pub operation: String,
    pub next: String,
    pub password: String,
    #[serde(default)]
    pub totp_code: Option<String>,
    pub csrf_token: String,
}

/// ゲートの判定結果（応答の形は呼び出し側の経路で変わるため、ここでは判定だけを返す）。
enum Gate {
    /// 操作を続けてよい。
    Pass,
    /// 本人確認が要る。値は誘導先の画面。
    Challenge(String),
    /// ログインからやり直し。
    LoginRequired,
    /// この経路の都合ではない失敗（api 不達・実装の不整合）。
    Failed(StatusCode),
}

/// ゲートの判定を 1 箇所に閉じる（HTML 経路も JSON 経路もここを通す）。
async fn evaluate(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    headers: &HeaderMap,
    operation: &str,
    next: &str,
) -> Gate {
    let Some(sso) = cookies::get(headers, cookies::SSO_SESSION_COOKIE) else {
        return Gate::LoginRequired;
    };
    let request = InternalStepUpCheckRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        operation: operation.to_string(),
    };
    match state.api.step_up_check(&correlation.0, &request).await {
        Ok(InternalStepUpCheckResponse::Satisfied) => Gate::Pass,
        Ok(InternalStepUpCheckResponse::ChallengeRequired { .. }) => {
            Gate::Challenge(challenge_path(tenant, operation, next))
        }
        Ok(InternalStepUpCheckResponse::SessionExpired) => Gate::LoginRequired,
        Ok(InternalStepUpCheckResponse::UnknownOperation) => {
            // 呼び出し側が定数で渡す値なので、ここに来るのは実装の不整合。fail-closed で止める。
            tracing::error!(operation, "step-up check rejected an unknown operation");
            Gate::Failed(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Ok(InternalStepUpCheckResponse::Internal) => {
            Gate::Failed(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(e) => {
            tracing::error!(error = %e, "step-up check call to api failed");
            Gate::Failed(internal_call_status(&e))
        }
    }
}

/// 重要操作の入口で呼ぶゲート（画面遷移を伴う HTML 経路用）。
///
/// `Ok(())` なら操作を続けてよい。`Err(response)` は呼び出し側がそのまま返す（本人確認画面への
/// リダイレクト、または未ログイン時のログイン画面への誘導）。
pub async fn require_step_up(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    headers: &HeaderMap,
    operation: &str,
    next: &str,
) -> Result<(), Response> {
    match evaluate(state, correlation, tenant, headers, operation, next).await {
        Gate::Pass => Ok(()),
        Gate::Challenge(path) => Err(found(&path)),
        Gate::LoginRequired => Err(found(&format!("{}/login", tenant.prefix()))),
        Gate::Failed(status) => Err(status.into_response()),
    }
}

/// 同じゲートの JSON API 用（`fetch` から呼ばれる更新系エンドポイント）。
///
/// **画面を出すハンドラだけを守っても意味がない。** 画面は入口の案内に過ぎず、実際に認証器を
/// 作るのは JSON エンドポイントで、盗んだ Cookie を持つ呼び出し元は画面を経由せず直接叩ける。
/// リダイレクトを返すと `fetch` が黙って追ってしまい HTML が JSON として読まれるため、こちらは
/// 403 に誘導先を載せて返し、遷移はスクリプトに行わせる。
pub async fn require_step_up_api(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    headers: &HeaderMap,
    operation: &str,
    next: &str,
) -> Result<(), Response> {
    match evaluate(state, correlation, tenant, headers, operation, next).await {
        Gate::Pass => Ok(()),
        Gate::Challenge(path) => Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "result": "step_up_required", "location": path })),
        )
            .into_response()),
        Gate::LoginRequired => Err(StatusCode::UNAUTHORIZED.into_response()),
        Gate::Failed(status) => Err(status.into_response()),
    }
}

/// 本人確認画面（`GET /{tenant_id}/settings/verify`）。
pub async fn page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<StepUpQuery>,
) -> Response {
    let locale = locale(&headers);
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    let operation = query.operation.unwrap_or_default();
    let next = safe_next(&tenant, query.next.as_deref());
    let csrf = console_csrf_token(&sso, state.config.csrf_secret());

    // 第二要素まで求めるかは api の判定に従う（画面が独自に推測すると要件とずれる）。
    let request = InternalStepUpCheckRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        operation: operation.clone(),
    };
    let (second_factor_required, passkey_available) =
        match state.api.step_up_check(&correlation.0, &request).await {
            Ok(InternalStepUpCheckResponse::ChallengeRequired {
                second_factor_required,
                passkey_available,
            }) => (second_factor_required, passkey_available),
            // もう満たしている（別タブで確認済み等）なら、そのまま戻す。
            Ok(InternalStepUpCheckResponse::Satisfied) => return found(&next),
            Ok(InternalStepUpCheckResponse::SessionExpired) => {
                return found(&format!("{}/login", tenant.prefix()));
            }
            Ok(InternalStepUpCheckResponse::UnknownOperation) => {
                return StatusCode::BAD_REQUEST.into_response();
            }
            Ok(InternalStepUpCheckResponse::Internal) => {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            Err(e) => {
                tracing::error!(error = %e, "step-up check call to api failed");
                return internal_call_status(&e).into_response();
            }
        };

    let messages = Messages::new(locale);
    Html(render(&StepUpChallenge {
        messages: &messages,
        tenant: &tenant.prefix(),
        csrf: &csrf,
        operation: &operation,
        next: &next,
        second_factor_required,
        passkey_available,
        error_key: query.error.as_deref().and_then(error_key_for),
    }))
    .into_response()
}

/// 本人確認の実行（`POST /{tenant_id}/settings/verify`）。
pub async fn verify(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<StepUpForm>,
) -> Response {
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    let next = safe_next(&tenant, Some(&form.next));
    let challenge = challenge_path(&tenant, &form.operation, &next);

    if !assay_contracts::csrf::verify(
        &console_csrf_token(&sso, state.config.csrf_secret()),
        &form.csrf_token,
    ) {
        tracing::warn!(
            correlation_id = %correlation.0,
            "step-up verification rejected: csrf token mismatch"
        );
        return see_other(&format!("{challenge}&error=csrf"));
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalStepUpVerifyRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        operation: form.operation.clone(),
        password: form.password,
        totp_code: form.totp_code,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .step_up_verify(&ctx.correlation_id, &request)
        .await
    {
        Ok(InternalStepUpVerifyResponse::Ok) => see_other(&next),
        Ok(InternalStepUpVerifyResponse::InvalidCredentials) => {
            see_other(&format!("{challenge}&error=invalid"))
        }
        Ok(InternalStepUpVerifyResponse::SecondFactorRequired) => {
            see_other(&format!("{challenge}&error=second-factor"))
        }
        Ok(InternalStepUpVerifyResponse::RateLimited) => {
            see_other(&format!("{challenge}&error=rate-limited"))
        }
        Ok(InternalStepUpVerifyResponse::SessionExpired) => {
            found(&format!("{}/login", tenant.prefix()))
        }
        Ok(InternalStepUpVerifyResponse::UnknownOperation) => {
            StatusCode::BAD_REQUEST.into_response()
        }
        Ok(InternalStepUpVerifyResponse::Internal) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "step-up verify call to api failed");
            internal_call_status(&e).into_response()
        }
    }
}

// ─── パスキーでの本人確認（T38） ─────────────────────────────────────────────
//
// ブラウザの WebAuthn API を通るため、フォーム送信ではなく JSON の 2 段構えになる。画面側は
// ログイン画面と同じ `assets/passkey-login.js` を使い、開始・完了のパスだけを差し替える。
//
// CSRF トークンを取らないのは、ログイン・登録のパスキー JSON API と同じ理由である。JSON を
// 受けるエンドポイントへの別オリジンからの POST はプリフライトを要し（CORS 許可は出していない）、
// そもそも通らない。加えて完了には**その利用者の認証器が今この場で作った署名**が要る。

/// パスキーでの本人確認の開始（`POST /{tenant_id}/settings/verify/passkey/begin`）。
pub async fn passkey_begin(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let request = InternalStepUpPasskeyBeginRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
    };
    match state
        .api
        .step_up_passkey_begin(&correlation.0, &request)
        .await
    {
        Ok(response @ InternalStepUpPasskeyBeginResponse::Ok { .. }) => {
            Json(response).into_response()
        }
        Ok(InternalStepUpPasskeyBeginResponse::SessionExpired) => {
            StatusCode::UNAUTHORIZED.into_response()
        }
        Ok(InternalStepUpPasskeyBeginResponse::Internal) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "step-up passkey begin call to api failed");
            internal_call_status(&e).into_response()
        }
    }
}

/// 完了 API が受け取る本文。`operation` と `next` は画面が `#passkey-error` の data 属性で
/// スクリプトへ渡した値がそのまま返ってくる（`next` はここで改めてこのテナントのパスに限定する ——
/// ブラウザから来た値を信用しない）。
#[derive(Debug, Deserialize)]
pub struct PasskeyCompleteBody {
    pub challenge_id: String,
    pub credential: serde_json::Value,
    #[serde(default)]
    pub operation: String,
    #[serde(default)]
    pub next: Option<String>,
}

/// パスキーでの本人確認の完了（`POST /{tenant_id}/settings/verify/passkey/complete`）。
///
/// 成功時は `{ redirect_to }` を返し、スクリプトがそこへ遷移する（フォーム経路の 303 に当たる）。
pub async fn passkey_complete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Json(body): Json<PasskeyCompleteBody>,
) -> Response {
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let next = safe_next(&tenant, body.next.as_deref());
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalStepUpPasskeyVerifyRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        operation: body.operation,
        challenge_id: body.challenge_id,
        credential: body.credential,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .step_up_passkey_verify(&ctx.correlation_id, &request)
        .await
    {
        Ok(InternalStepUpPasskeyVerifyResponse::Ok) => Json(json!({ "redirect_to": next })),
        Ok(InternalStepUpPasskeyVerifyResponse::InvalidCredential) => {
            Json(json!({ "error": "invalid_credential" }))
        }
        Ok(InternalStepUpPasskeyVerifyResponse::RateLimited) => {
            Json(json!({ "error": "rate_limited" }))
        }
        // 文言を出しても打つ手が無いので、ログインからやり直させる（登録画面の 401 と同じ扱い）。
        Ok(InternalStepUpPasskeyVerifyResponse::SessionExpired) => {
            Json(json!({ "redirect_to": format!("{}/login", tenant.prefix()) }))
        }
        Ok(InternalStepUpPasskeyVerifyResponse::UnknownOperation) => {
            // 画面が渡す値なので、ここに来るのは実装の不整合。fail-closed で止める。
            tracing::error!("step-up passkey verify rejected an unknown operation");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Ok(InternalStepUpPasskeyVerifyResponse::Internal) => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "step-up passkey verify call to api failed");
            return internal_call_status(&e).into_response();
        }
    }
    .into_response()
}

/// 本人確認画面への URL を組み立てる。
fn challenge_path(tenant: &WebTenant, operation: &str, next: &str) -> String {
    fn encode(value: &str) -> String {
        percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
    }
    format!(
        "{}/settings/verify?operation={}&next={}",
        tenant.prefix(),
        encode(operation),
        encode(next)
    )
}

/// `next` をこのテナント配下のパスに限定する（オープンリダイレクト防止）。
///
/// 受け付けるのは `/{tenant_id}` で始まり、かつ 2 文字目が `/` でないパスだけ。`//host` は
/// スキーム相対 URL としてブラウザが別オリジンへ解決するため、先頭が `/` であることだけでは
/// 不十分。条件を満たさない値は設定画面へ倒す。
fn safe_next(tenant: &WebTenant, next: Option<&str>) -> String {
    let fallback = format!("{}/settings", tenant.prefix());
    let Some(candidate) = next.filter(|v| !v.is_empty()) else {
        return fallback;
    };
    let prefix = tenant.prefix();
    // 接頭辞の一致は `strip_prefix` で見る。**バイト位置で切ってはいけない** —— 接頭辞より短い
    // `next`（`/settings` など。テナント接頭辞は UUID で 37 文字ある）や、途中が文字境界でない
    // 値でパニックする。
    let Some(rest) = candidate.strip_prefix(prefix.as_str()) else {
        return fallback;
    };
    // `\` はブラウザによって `/` として解釈されるため、`//` と同じ理由で拒否する。
    if candidate.starts_with("//") || candidate.contains('\\') {
        return fallback;
    }
    // 「別テナントの接頭辞が偶然一致する」ことを避けるため、接頭辞の直後が区切りか終端かまで見る
    // （`/t1` に対する `/t123/...` を通さない）。
    if rest.is_empty() || rest.starts_with('/') || rest.starts_with('?') {
        candidate.to_string()
    } else {
        fallback
    }
}

fn error_key_for(value: &str) -> Option<&'static str> {
    match value {
        "csrf" => Some("step-up-error-csrf"),
        "invalid" => Some("step-up-error-invalid"),
        "second-factor" => Some("step-up-error-second-factor"),
        "rate-limited" => Some("login-error-rate-limited"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> WebTenant {
        WebTenant("t1".to_string())
    }

    /// 同一テナント配下のパスだけを受け付ける（オープンリダイレクトを作らない）。
    #[test]
    fn next_is_restricted_to_this_tenants_paths() {
        let t = tenant();
        assert_eq!(
            safe_next(&t, Some("/t1/account/passkey")),
            "/t1/account/passkey"
        );
        assert_eq!(safe_next(&t, Some("/t1")), "/t1");
        assert_eq!(safe_next(&t, Some("/t1?x=1")), "/t1?x=1");

        let fallback = "/t1/settings";
        // 外部オリジン・スキーム相対・バックスラッシュ・別テナント・空。
        assert_eq!(safe_next(&t, Some("https://evil.example.com")), fallback);
        assert_eq!(safe_next(&t, Some("//evil.example.com")), fallback);
        assert_eq!(safe_next(&t, Some("/t1\\@evil.example.com")), fallback);
        assert_eq!(safe_next(&t, Some("/t2/admin")), fallback);
        assert_eq!(safe_next(&t, Some("/t123/admin")), fallback);
        assert_eq!(safe_next(&t, Some("")), fallback);
        assert_eq!(safe_next(&t, None), fallback);
    }

    /// **接頭辞より短い `next` で落ちない。** テナント接頭辞は UUID で 37 文字あるので、
    /// `?next=/x` のような短い値はごく普通に飛んでくる（バイト位置で切ると添字が範囲外になる）。
    #[test]
    fn a_next_shorter_than_the_tenant_prefix_falls_back_instead_of_panicking() {
        let t = WebTenant("00000000-0000-7000-8000-000000000001".to_string());
        let fallback = "/00000000-0000-7000-8000-000000000001/settings";
        assert_eq!(safe_next(&t, Some("/x")), fallback);
        assert_eq!(safe_next(&t, Some("https://evil.example.com/")), fallback);
        // 文字境界でない位置で切らない（マルチバイト文字を含む値）。
        assert_eq!(safe_next(&t, Some("/日本語のパス")), fallback);
    }

    /// 画面 URL は operation・next をパーセントエンコードして埋め込む。
    #[test]
    fn challenge_path_encodes_its_parameters() {
        let path = challenge_path(&tenant(), "manage_authenticators", "/t1/account/passkey");
        assert!(path.starts_with("/t1/settings/verify?"));
        assert!(path.contains("operation=manage%5Fauthenticators"));
        assert!(path.contains("next=%2Ft1%2Faccount%2Fpasskey"));
    }

    #[test]
    fn only_known_error_values_map_to_message_keys() {
        assert_eq!(error_key_for("invalid"), Some("step-up-error-invalid"));
        assert_eq!(error_key_for("<script>"), None);
    }
}
