//! Step-up 認証の本人確認画面（web。`/{tenant_id}/settings/verify`。AP5）。
//!
//! 重要操作（認証器の追加削除・セッション失効など）の入口で [`require_step_up`] を呼び、足りなければ
//! この画面へ誘導する。確認が通ったら元の画面（`next`）へ戻す。
//!
//! 判定と検証は api（`/internal/step-up/*`）が行い、web は画面と `next` の安全性だけを担う。
//!
//! # `next` の扱い
//!
//! `next` はブラウザから任意の値が渡る。同一オリジン内の**このテナントのパス**に限って受け付ける
//! （オープンリダイレクトを作らないため）。`//evil.example.com` のような「スキームなし絶対 URL」は
//! ブラウザが別オリジンとして解決するので、単に先頭が `/` かどうかでは足りない。

use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::handlers::{forwarded_context, found, locale, see_other};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, StepUpChallenge};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::auth::{
    InternalStepUpCheckRequest, InternalStepUpCheckResponse, InternalStepUpVerifyRequest,
    InternalStepUpVerifyResponse,
};
use serde::Deserialize;

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

/// 重要操作の入口で呼ぶゲート。
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
    let Some(sso) = cookies::get(headers, cookies::SSO_SESSION_COOKIE) else {
        return Err(found(&format!("{}/login", tenant.prefix())));
    };
    let request = InternalStepUpCheckRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        operation: operation.to_string(),
    };
    match state.api.step_up_check(&correlation.0, &request).await {
        Ok(InternalStepUpCheckResponse::Satisfied) => Ok(()),
        Ok(InternalStepUpCheckResponse::ChallengeRequired { .. }) => {
            Err(found(&challenge_path(tenant, operation, next)))
        }
        Ok(InternalStepUpCheckResponse::SessionExpired) => {
            Err(found(&format!("{}/login", tenant.prefix())))
        }
        Ok(InternalStepUpCheckResponse::UnknownOperation) => {
            // 呼び出し側が定数で渡す値なので、ここに来るのは実装の不整合。fail-closed で止める。
            tracing::error!(operation, "step-up check rejected an unknown operation");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Ok(InternalStepUpCheckResponse::Internal) => {
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Err(e) => {
            tracing::error!(error = %e, "step-up check call to api failed");
            Err(StatusCode::BAD_GATEWAY.into_response())
        }
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
    let second_factor_required = match state.api.step_up_check(&correlation.0, &request).await {
        Ok(InternalStepUpCheckResponse::ChallengeRequired {
            second_factor_required,
        }) => second_factor_required,
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
            return StatusCode::BAD_GATEWAY.into_response();
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
        error_key: query.error.as_deref().and_then(error_key_for),
    }))
    .into_response()
}

/// 本人確認の実行（`POST /{tenant_id}/settings/verify`）。
pub async fn verify(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<StepUpForm>,
) -> Response {
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    let next = safe_next(&tenant, Some(&form.next));
    let challenge = challenge_path(&tenant, &form.operation, &next);

    if console_csrf_token(&sso, state.config.csrf_secret()) != form.csrf_token {
        tracing::warn!(
            correlation_id = %correlation.0,
            "step-up verification rejected: csrf token mismatch"
        );
        return see_other(&format!("{challenge}&error=csrf"));
    }

    let ctx = forwarded_context(&headers, &correlation);
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
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
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
    let looks_local = candidate.starts_with(&prefix)
        && !candidate.starts_with("//")
        // `\` はブラウザによって `/` として解釈されるため、同じ理由で拒否する。
        && !candidate.contains('\\');
    // プレフィクス一致は「別テナントの接頭辞が偶然一致する」ことを避けるため、直後が区切りか終端か
    // まで見る（`/t1` に対する `/t123/...` を通さない）。
    let boundary_ok = candidate.len() == prefix.len()
        || candidate[prefix.len()..].starts_with('/')
        || candidate[prefix.len()..].starts_with('?');
    if looks_local && boundary_ok {
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
        assert_eq!(safe_next(&t, Some("/t1/account/passkey")), "/t1/account/passkey");
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
