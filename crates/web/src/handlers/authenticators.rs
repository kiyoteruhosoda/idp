//! 認証器の管理画面（web。`/{tenant_id}/settings/authenticators`。AP9）。
//!
//! 種別（TOTP・パスキー）を横断した登録簿を 1 画面で見せ、一時停止・再開・失効と、
//! リカバリーコードの発行を提供する。判定と永続化は api（`/internal/account/authenticators*`）が
//! 行い、web は CSRF・step-up ゲート・描画だけを担う。
//!
//! 認証器を触る操作はすべて step-up（AP5）の対象。盗まれたセッションで認証器を足されると、
//! 以後は正規の資格情報として振る舞われてしまう。

use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::handlers::{forwarded_context, found, locale, see_other, step_up};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, AuthenticatorView, RecoveryCodes, UserAuthenticators};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::auth::{
    InternalAuthenticatorStatusRequest, InternalAuthenticatorStatusResponse,
    InternalAuthenticatorsRequest, InternalAuthenticatorsResponse, InternalRecoveryCodesRequest,
    InternalRecoveryCodesResponse,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AuthenticatorsQuery {
    #[serde(default)]
    pub saved: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StatusForm {
    pub authenticator_id: String,
    /// `suspended` / `active` / `revoked`。
    pub status: String,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct RecoveryCodesForm {
    pub csrf_token: String,
}

/// 認証器一覧（`GET /{tenant_id}/settings/authenticators`）。
pub async fn page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<AuthenticatorsQuery>,
) -> Response {
    let locale = locale(&headers);
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    let csrf = console_csrf_token(&sso, state.config.csrf_secret());

    let request = InternalAuthenticatorsRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
    };
    let outcome = match state
        .api
        .account_authenticators(&correlation.0, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "authenticator list call to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    let (authenticators, recovery_codes_remaining) = match outcome {
        InternalAuthenticatorsResponse::Ok {
            authenticators,
            recovery_codes_remaining,
        } => (authenticators, recovery_codes_remaining),
        InternalAuthenticatorsResponse::SessionExpired => {
            return found(&format!("{}/login", tenant.prefix()));
        }
        InternalAuthenticatorsResponse::Internal => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let messages = Messages::new(locale);
    let views: Vec<AuthenticatorView> = authenticators
        .into_iter()
        .map(|a| AuthenticatorView {
            // 種別・状態は翻訳キーに写す（生の値を画面へ出すと英語のまま混ざる）。
            type_key: type_message_key(&a.authenticator_type),
            status_key: status_message_key(&a.status),
            suspendable: a.status == "active",
            resumable: a.status == "suspended",
            id: a.id,
            label: a.label,
            created_at: a.created_at,
            last_used_at: a.last_used_at.unwrap_or_default(),
        })
        .collect();

    Html(render(&UserAuthenticators {
        messages: &messages,
        tenant: &tenant.prefix(),
        csrf: &csrf,
        authenticators: &views,
        recovery_codes_remaining,
        saved_key: query.saved.as_deref().and_then(saved_key_for),
        error_key: query.error.as_deref().and_then(error_key_for),
    }))
    .into_response()
}

/// 認証器の状態変更（`POST /{tenant_id}/settings/authenticators/status`）。
pub async fn set_status(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<StatusForm>,
) -> Response {
    let base = format!("{}/settings/authenticators", tenant.prefix());
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if console_csrf_token(&sso, state.config.csrf_secret()) != form.csrf_token {
        return see_other(&format!("{base}?error=csrf"));
    }
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        step_up::MANAGE_AUTHENTICATORS,
        &base,
    )
    .await
    {
        return response;
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalAuthenticatorStatusRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        authenticator_id: form.authenticator_id,
        status: form.status,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .account_authenticator_status(&ctx.correlation_id, &request)
        .await
    {
        Ok(InternalAuthenticatorStatusResponse::Ok) => see_other(&format!("{base}?saved=status")),
        Ok(InternalAuthenticatorStatusResponse::NotFound) => {
            see_other(&format!("{base}?error=not-found"))
        }
        Ok(InternalAuthenticatorStatusResponse::InvalidTransition)
        | Ok(InternalAuthenticatorStatusResponse::UnknownStatus) => {
            see_other(&format!("{base}?error=transition"))
        }
        Ok(InternalAuthenticatorStatusResponse::SessionExpired) => {
            found(&format!("{}/login", tenant.prefix()))
        }
        Ok(InternalAuthenticatorStatusResponse::Internal) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "authenticator status call to api failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// リカバリーコードの発行（`POST /{tenant_id}/settings/recovery-codes`）。
///
/// 平文は**この応答でしか表示しない**。PRG にせず結果を直接描画するのは、リダイレクトすると
/// コードを URL かサーバ側の一時領域に載せることになるため（どちらも残したくない）。
pub async fn issue_recovery_codes(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<RecoveryCodesForm>,
) -> Response {
    let base = format!("{}/settings/authenticators", tenant.prefix());
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if console_csrf_token(&sso, state.config.csrf_secret()) != form.csrf_token {
        return see_other(&format!("{base}?error=csrf"));
    }
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        step_up::MANAGE_AUTHENTICATORS,
        &base,
    )
    .await
    {
        return response;
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalRecoveryCodesRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let codes = match state
        .api
        .account_recovery_codes(&ctx.correlation_id, &request)
        .await
    {
        Ok(InternalRecoveryCodesResponse::Ok { codes }) => codes,
        Ok(InternalRecoveryCodesResponse::SessionExpired) => {
            return found(&format!("{}/login", tenant.prefix()));
        }
        Ok(InternalRecoveryCodesResponse::Internal) => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "recovery code issuance call to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let messages = Messages::new(locale(&headers));
    Html(render(&RecoveryCodes {
        messages: &messages,
        tenant: &tenant.prefix(),
        codes: &codes,
    }))
    .into_response()
}

/// 認証器の種別を翻訳キーへ写す（未知の値は「その他」へ倒す）。
fn type_message_key(value: &str) -> &'static str {
    match value {
        "totp" => "authenticator-type-totp",
        "webauthn" => "authenticator-type-webauthn",
        "email_otp" => "authenticator-type-email-otp",
        "sms_otp" => "authenticator-type-sms-otp",
        "recovery_code" => "authenticator-type-recovery-code",
        _ => "authenticator-type-unknown",
    }
}

fn status_message_key(value: &str) -> &'static str {
    match value {
        "pending" => "authenticator-status-pending",
        "active" => "authenticator-status-active",
        "suspended" => "authenticator-status-suspended",
        "revoked" => "authenticator-status-revoked",
        _ => "authenticator-status-unknown",
    }
}

fn saved_key_for(value: &str) -> Option<&'static str> {
    match value {
        "status" => Some("authenticator-saved-status"),
        _ => None,
    }
}

fn error_key_for(value: &str) -> Option<&'static str> {
    match value {
        "csrf" => Some("user-security-error-csrf"),
        "not-found" => Some("authenticator-error-not-found"),
        "transition" => Some("authenticator-error-transition"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// api が返す種別・状態はそのまま画面へ出さず、必ず翻訳キーへ写す
    /// （新しい値が増えたときに生の英語識別子が画面へ漏れないようにする）。
    #[test]
    fn unknown_types_and_statuses_fall_back_to_a_known_key() {
        assert_eq!(type_message_key("totp"), "authenticator-type-totp");
        assert_eq!(type_message_key("quantum"), "authenticator-type-unknown");
        assert_eq!(status_message_key("active"), "authenticator-status-active");
        assert_eq!(status_message_key("weird"), "authenticator-status-unknown");
    }

    #[test]
    fn only_known_banner_values_map_to_message_keys() {
        assert_eq!(saved_key_for("status"), Some("authenticator-saved-status"));
        assert_eq!(saved_key_for("<script>"), None);
        assert_eq!(error_key_for("anything"), None);
    }
}
